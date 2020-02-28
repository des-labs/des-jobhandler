import tornado.ioloop
import tornado.web
import tornado
import json
import jwt
import datetime
import mysql.connector
import logging
import uuid
import kubejob
import os
import secrets
SECRET = 'my_secret_key'

log_format = "%(asctime)s  %(name)8s  %(levelname)5s  %(message)s"
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.FileHandler("test.log"), logging.StreamHandler()],
    format=log_format,
)
logger = logging.getLogger("main")


def get_jobid():
    return str(uuid.uuid4()).replace("-", "")


def register_job(conf):
    cnx, cur = open_db_connection()

    newJobSql = (
        "INSERT INTO Jobs "
        "(user, job, name, status, time, type, query, files, sizes, runtime, apitoken) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )
    newJobInfo = (
        conf["configjob"]["username"],
        conf["job"],
        conf["configjob"]["jobid"],
        'in_progress',
        datetime.datetime.utcnow(),
        'type_test',
        'query_test',
        'files_test',
        'sizes_test',
        0,
        conf["configjob"]["apitoken"]
    )
    cur.execute(newJobSql, newJobInfo)
    close_db_connection(cnx, cur)


def submit_test(body):
    username = body["username"].lower()
    time = int(body["time"])
    job = body["job"]
    jobid = get_jobid()
    conf = {"job": job}
    # When running in a pod, the namespace should be determined automatically,
    # otherwise we assume the local development is in the default namespace
    try:
        with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as file:
            namespace = file.read().replace('\n', '')
    except:
        namespace = 'default'
    conf["namespace"] = namespace
    conf["cm_name"] = "{}-{}-{}-cm".format(conf["job"], jobid, username)
    conf["job_name"] = "{}-{}-{}".format(conf["job"], jobid, username)
    conf["image"] = os.environ['DOCKER_IMAGE']
    conf["command"] = ["python", "task.py"]
    conf["configjob"] = {
        "name": conf["job"],
        "jobid": jobid,
        "username": username,
        "inputs": {"time": time},
        "outputs": {"log": "{}.log".format(conf["job"])},
        "apitoken": secrets.token_hex(16),
        "api_base_url": os.environ['API_BASE_URL']
    }
    conf['pvc_name'] = "deslabs-legacy-task-test"
    kubejob.create_configmap(conf)
    kubejob.create_job(conf)
    msg = "Job:{} id:{} by:{}".format(conf["job"], jobid, username)
    register_job(conf)
    return msg


class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Content-Type")
        self.set_header("Access-Control-Allow-Methods",
                        " POST, PUT, DELETE, OPTIONS")

    def options(self):
        self.set_status(204)
        self.finish()

    def getarg(self, arg, default=""):
        temp = self.get_argument(arg, default)
        try:
            data_json = tornado.escape.json_decode(self.request.body)
            temp = default
            temp = data_json[arg]
        except:
            pass
        return temp


class ProfileHandler(BaseHandler):
    # API endpoint: /profile
    def post(self):
        body = {k: self.get_argument(k) for k in self.request.arguments}
        token = body["token"]
        decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
        exptime = datetime.datetime.utcfromtimestamp(decoded['exp'])
        ttl = (exptime - datetime.datetime.utcnow()).seconds
        logger.info(ttl)
        response = {
            'username': decoded["username"],
            "email": decoded["email"],
            "ttl": ttl
        }
        logger.info(response)
        self.write(response)


class LoginHandler(BaseHandler):
    # API endpoint: /login
    def post(self):
        body = {k: self.get_argument(k) for k in self.request.arguments}
        username = body["username"]
        #passwd = body["password"]
        email = "{}@test.test".format(username)
        encoded = jwt.encode({
            'username': username,
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=600)},
            SECRET,
            algorithm='HS256'
        )
        response = {
            'username': username,
            'email': email,
            'token': encoded.decode(encoding='UTF-8')
        }
        self.write(json.dumps(response))


class JobHandler(BaseHandler):
    # API endpoint: /job/submit
    def put(self):
        body = {k: self.get_argument(k) for k in self.request.arguments}
        logger.info(body)
        job = body["job"]
        if job == "test":
           msg = submit_test(body)
           logger.info(msg)
        else:
            msg = 'Job {} not defined'.format(job)
        out = dict(msg=msg)
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/delete
    def delete(self):
        username = self.getarg("username")
        job = self.getarg("job")
        jobid = self.getarg("jobid")
        conf = {"job": job}
        conf["namespace"] = "default"
        conf["job_name"] = "{}-{}-{}".format(conf["job"], jobid, username)
        conf["cm_name"] = "{}-{}-{}-cm".format(conf["job"], jobid, username)
        kubejob.delete_job(conf)
        out = dict(msg="done")
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/status
    def post(self):
        username = self.getarg("username")
        job = self.getarg("job")
        jobid = self.getarg("jobid")
        conf = {"job": job}
        conf["namespace"] = "default"
        conf["job_name"] = "{}-{}-{}".format(conf["job"], jobid, username)
        status = kubejob.status_job(conf)
        out = dict(
            msg="done",
            avtive=status.active,
            succeeded=status.succeeded,
            failed=status.failed,
        )
        self.write(json.dumps(out, indent=4))


## This is the one providing a list of hidden/allowed resources
class InitHandler(BaseHandler):
    # API endpoint: /init
    def post(self):
        cnx, cur = open_db_connection()
        username = self.getarg("username")
        logger.info(username)
        t = cur.execute(
            "select pages from access where username = '{}'".format(username))
        d = t.fetchone()
        close_db_connection(cnx, cur)
        pages = []
        if d is not None:
            pages = d[0].replace(" ", "").split(",")
        out = dict(access=pages)
        self.write(json.dumps(out, indent=4))


class JobMonitor(BaseHandler):
    # API endpoint: /job/monitor
    def post(self):
        try:
            data = json.loads(self.request.body.decode('utf-8'))
            logger.info('/job/monitor data: {}'.format(json.dumps(data)))
        except:
            logger.info('Error decoding JSON data')
            self.write({
                "status": "error",
                "reason": "Invalid JSON in HTTP request body."
            })
            return
        apitoken = data["apitoken"]
        logger.info('API token: {}'.format(apitoken))
        cnx, cur = open_db_connection()
        cur.execute(
            "SELECT id FROM Jobs WHERE apitoken = '{}' LIMIT 1".format(apitoken)
        )
        id = cur.fetchone()
        if id is not None:
            updateJobSql = (
                "UPDATE Jobs "
                "SET status=%s "
                "WHERE id=%s"
            )
            updateJobInfo = (
                'complete',
                id[0]
            )
            cur.execute(updateJobSql, updateJobInfo)
        close_db_connection(cnx, cur)

def make_app(basePath=''):
    settings = {"debug": True}
    return tornado.web.Application(
        [
            (r"{}/job/status?".format(basePath), JobHandler),
            (r"{}/job/delete?".format(basePath), JobHandler),
            (r"{}/job/submit?".format(basePath), JobHandler),
            (r"{}/login/?".format(basePath), LoginHandler),
            (r"{}/profile/?".format(basePath), ProfileHandler),
            (r"{}/init/?".format(basePath), InitHandler),
            (r"{}/job/monitor?".format(basePath), JobMonitor),
        ],
        **settings
    )


def close_db_connection(cnx, cur):
    # Commit changes to database and close connection
    cnx.commit()
    cur.close()
    cnx.close()


def open_db_connection():
    # Open database connection
    cnx = mysql.connector.connect(
        host=os.environ['MYSQL_HOST'],
        user=os.environ['MYSQL_USER'],
        password=os.environ['MYSQL_PASSWORD'],
        database=os.environ['MYSQL_DATABASE'],
    )
    # Get database cursor object
    cur = cnx.cursor()
    return cnx, cur


def create_db_jobs_table(delete=False):

    cnx, cur = open_db_connection()

    # Create the database table "Jobs"
    with open(os.path.join(os.path.dirname(__file__), "db_schema.sql")) as f:
        dbSchema = f.read()
    if delete:
        cur.execute("DROP TABLE IF EXISTS Jobs")
    cur.execute(dbSchema)

    close_db_connection(cnx, cur)


if __name__ == "__main__":

    if int(os.environ['SERVICE_PORT']):
        servicePort = int(os.environ['SERVICE_PORT'])
    else:
        servicePort = 8080
    if os.environ['BASE_PATH'] == '' or os.environ['BASE_PATH'] == '/' or not isinstance(os.environ['BASE_PATH'], str):
        basePath = ''
    else:
        basePath = os.environ['BASE_PATH']

    # Create the MySQL database table for storing Jobs
    create_db_jobs_table(delete=True)

    app = make_app(basePath=basePath)
    app.listen(servicePort)
    tornado.ioloop.IOLoop.current().start()
