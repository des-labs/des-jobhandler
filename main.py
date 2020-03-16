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
import yaml
from jinja2 import Template
import dbutils
import tests
SECRET = 'my_secret_key'

# Import environment variable values
DOCKER_IMAGE = os.environ['DOCKER_IMAGE']
API_BASE_URL = os.environ['API_BASE_URL']
PVC_NAME = os.environ['PVC_NAME']
MYSQL_HOST = os.environ['MYSQL_HOST']
MYSQL_DATABASE = os.environ['MYSQL_DATABASE']
MYSQL_USER = os.environ['MYSQL_USER']
MYSQL_PASSWORD = os.environ['MYSQL_PASSWORD']
SERVICE_PORT = os.environ['SERVICE_PORT']
BASE_PATH = os.environ['BASE_PATH']

log_format = "%(asctime)s  %(name)8s  %(levelname)5s  %(message)s"
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.FileHandler("test.log"), logging.StreamHandler()],
    format=log_format,
)
logger = logging.getLogger("main")


def get_jobid():
    return str(uuid.uuid4()).replace("-", "")


def get_job_name(jobType, jobId, username):
    return "{}-{}-{}".format(jobType, jobId, username)


def get_job_configmap_name(jobType, jobId, username):
    return "{}-{}-{}-cm".format(jobType, jobId, username)


def register_job(conf):
    cnx, cur = open_db_connection()

    newJobSql = (
        "INSERT INTO Jobs "
        "(user, job, name, status, time_start, time_complete, type, query, files, sizes, runtime, apitoken, spec) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )
    newJobInfo = (
        conf["configjob"]["metadata"]["username"],
        conf["job"],
        conf["configjob"]["metadata"]["jobId"],
        'init',
        None,
        None,
        'type_test',
        'query_test',
        'files_test',
        'sizes_test',
        0,
        conf["configjob"]["metadata"]["apiToken"],
        json.dumps(conf["configjob"]["spec"])

    )
    cur.execute(newJobSql, newJobInfo)
    close_db_connection(cnx, cur)


def submit_test(body):
    username = body["username"].lower()
    time = int(body["time"])
    job = body["job"]
    jobid = get_jobid()
    conf = {"job": job}
    conf["namespace"] = get_namespace()
    conf["cm_name"] = get_job_configmap_name(conf["job"], jobid, username)
    conf["job_name"] = get_job_name(conf["job"], jobid, username)
    conf["image"] = DOCKER_IMAGE
    conf["command"] = ["python", "task.py"]

    # Import task config template file and populate with values
    jobConfigTemplateFile = os.path.join(
        os.path.dirname(__file__),
        "des-tasks",
        job,
        "jobconfig.tpl.yaml"
    )
    with open(jobConfigTemplateFile) as f:
        templateText = f.read()
    template = Template(templateText)
    conf["configjob"] = yaml.safe_load(template.render(
        taskType=conf["job"],
        jobName=conf["job_name"],
        jobId=jobid,
        username=username,
        taskDuration=time,
        logFilePath="./output/{}.log".format(conf["job_name"]),
        apiToken=secrets.token_hex(16),
        apiBaseUrl=API_BASE_URL,
        persistentVolumeClaim=PVC_NAME
    ))

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
        response = {}
        try:
            decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
            exptime = datetime.datetime.utcfromtimestamp(decoded['exp'])
            ttl = (exptime - datetime.datetime.utcnow()).seconds
            response["status"] = "ok"
            response["message"] = "valid token"
            response["name"] = decoded["name"]
            response["username"] = decoded["username"]
            response["email"] = decoded["email"]
            response["ttl"] = ttl
        except jwt.InvalidSignatureError:
            response["status"] = "error"
            response["message"] = "Signature verification failed"
            self.set_status(401)
        except jwt.ExpiredSignatureError:
            response["status"] = "error"
            response["message"] = "Signature has expired"
            self.set_status(401)
        except jwt.DecodeError:
            response["status"] = "error"
            response["message"] = "Invalid header string"
            self.set_status(500)
        self.flush()
        self.write(response)
        self.finish()
        return


class LoginHandler(BaseHandler):
    # API endpoint: /login
    def post(self):
        body = {k: self.get_argument(k) for k in self.request.arguments}
        username = body["username"]
        passwd = body["password"]
        db = body["database"]
        response = {"username": username}
        auth, err, update = dbutils.check_credentials(username, passwd, db)
        if not auth:
            if update:
                self.set_status(406)
                response["update"] = True
            else:
                self.set_status(401)
                response["update"] = False
            response["status"] = "error"
            response["message"] = err
            self.flush()
            self.write(json.dumps(response))
            self.finish()
            return
        # TODO: use des user manager credentials
        name, last, email = dbutils.get_basic_info(username, passwd, username)
        encoded = jwt.encode({
            'name': name,
            'username': username,
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60)},
            SECRET,
            algorithm='HS256'
        )
        response["status"] = "ok"
        response["message"] = "login"
        response["name"] = name
        response["email"] = email
        response["token"] = encoded.decode(encoding='UTF-8')
        self.write(json.dumps(response))


class JobHandler(BaseHandler):
    # API endpoint: /job/submit
    def put(self):
        body = {k: self.get_argument(k) for k in self.request.arguments}
        logger.info(body)
        jobType = body["job"]
        if jobType == "test":
           msg = submit_test(body)
           logger.info(msg)
        else:
            msg = 'Job type "{}" is not defined'.format(jobType)
        out = dict(msg=msg)
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/delete
    def delete(self):
        username = self.getarg("username")
        job = self.getarg("job")
        jobid = self.getarg("jobid")
        conf = {"job": job}
        #conf["namespace"] = "default"
        conf["job_name"] = get_job_name(conf["job"], jobid, username)
        conf["cm_name"] = get_job_configmap_name(conf["job"], jobid, username)
        kubejob.delete_job(conf)
        out = dict(msg="done")
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/status
    def post(self):
        username = self.getarg("username")
        job = self.getarg("job")
        jobid = self.getarg("jobid")
        conf = {"job": job}
        #conf["namespace"] = "default"
        conf["job_name"] = get_job_name(conf["job"], jobid, username)
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


class JobStart(BaseHandler):
    # API endpoint: /job/start
    def post(self):
        try:
            data = json.loads(self.request.body.decode('utf-8'))
            logger.info('/job/start data: {}'.format(json.dumps(data)))
        except:
            logger.info('Error decoding JSON data')
            self.write({
                "status": "error",
                "reason": "Invalid JSON in HTTP request body."
            })
            return
        apitoken = data["apitoken"]
        rowId = validate_apitoken(apitoken)
        if isinstance(rowId, int):
            cnx, cur = open_db_connection()
            updateJobSql = (
                "UPDATE Jobs "
                "SET status=%s, time_start=%s "
                "WHERE id=%s"
            )
            updateJobInfo = (
                'started',
                datetime.datetime.utcnow(),
                rowId
            )
            cur.execute(updateJobSql, updateJobInfo)
            if cur.rowcount != 1:
                logger.info('Error updating job record')
            close_db_connection(cnx, cur)


class JobComplete(BaseHandler):
    # API endpoint: /job/complete
    def post(self):
        try:
            data = json.loads(self.request.body.decode('utf-8'))
            logger.info('/job/complete data: {}'.format(json.dumps(data)))
        except:
            logger.info('Error decoding JSON data')
            self.write({
                "status": "error",
                "reason": "Invalid JSON in HTTP request body."
            })
            return
        apitoken = data["apitoken"]
        rowId = validate_apitoken(apitoken)
        if isinstance(rowId, int):
            cnx, cur = open_db_connection()
            updateJobSql = (
                "UPDATE Jobs "
                "SET status=%s, time_complete=%s "
                "WHERE id=%s"
            )
            updateJobInfo = (
                'complete',
                datetime.datetime.utcnow(),
                rowId
            )
            cur.execute(updateJobSql, updateJobInfo)
            if cur.rowcount != 1:
                logger.info('Error updating job record')
            else:
                selectJobSql = (
                    "SELECT user,job,name from Jobs WHERE id=%s"
                )
                selectJobInfo = (
                    rowId,
                )
                cur.execute(selectJobSql, selectJobInfo)
                for (user, job, name) in cur:
                    conf = {"job": job}
                    conf['namespace'] = get_namespace()
                    conf["job_name"] = get_job_name(conf["job"], name, user)
                    conf["cm_name"] = get_job_configmap_name(
                        conf["job"], name, user)
                    kubejob.delete_job(conf)
            close_db_connection(cnx, cur)


class TestConcurrency(BaseHandler):
    # API endpoint: /test/concurrency
    def post(self):
        try:
            data = json.loads(self.request.body.decode('utf-8'))
            if data["password"] == MYSQL_PASSWORD:
                tests.run_concurrency_tests()
        except:
            logger.info('Error decoding JSON data or invalid password')
            self.write({
                "status": "error",
                "reason": "Invalid JSON in HTTP request body or invalid password."
            })


def get_namespace():
    # When running in a pod, the namespace should be determined automatically,
    # otherwise we assume the local development is in the default namespace
    try:
        with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as file:
            namespace = file.read().replace('\n', '')
    except:
        if os.environ['NAMESPACE']:
            namespace = os.environ['NAMESPACE']
        else:
            namespace = 'default'
    return namespace


def validate_apitoken(apitoken):
    cnx, cur = open_db_connection()
    cur.execute(
        "SELECT id FROM Jobs WHERE apitoken = '{}' LIMIT 1".format(apitoken)
    )
    # If there is a result, assume only one exists and return the record id, otherwise return None
    rowId = None
    for (id,) in cur:
        rowId = id
    close_db_connection(cnx, cur)
    return rowId


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
            (r"{}/job/complete?".format(basePath), JobComplete),
            (r"{}/job/start?".format(basePath), JobStart),
            (r"{}/test/concurrency?".format(basePath), TestConcurrency),
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
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
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

    if int(SERVICE_PORT):
        servicePort = int(SERVICE_PORT)
    else:
        servicePort = 8080
    if BASE_PATH == '' or BASE_PATH == '/' or not isinstance(BASE_PATH, str):
        basePath = ''
    else:
        basePath = BASE_PATH

    # Create the MySQL database table for storing Jobs
    create_db_jobs_table(delete=True)

    app = make_app(basePath=basePath)
    app.listen(servicePort)
    tornado.ioloop.IOLoop.current().start()
