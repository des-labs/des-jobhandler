import rpdb
import tornado.ioloop
import tornado.web
import tornado
import json
import datetime
import logging
import kubejob
import dbutils
from jwtutils import authenticated
from jwtutils import encode_info
import tests
# from jobsdb import JobsDb
import envvars
import jobutils

# Get global instance of the job handler database interface
JOBSDB = jobutils.JobsDb(
    mysql_host=envvars.MYSQL_HOST,
    mysql_user=envvars.MYSQL_USER,
    mysql_password=envvars.MYSQL_PASSWORD,
    mysql_database=envvars.MYSQL_DATABASE
)

log_format = "%(asctime)s  %(name)8s  %(levelname)5s  %(message)s"
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.FileHandler("test.log"), logging.StreamHandler()],
    format=log_format,
)
logger = logging.getLogger("main")

class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
        self.set_header("Access-Control-Allow-Methods",
                        " POST, PUT, DELETE, OPTIONS, GET")

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


@authenticated
class ProfileHandler(BaseHandler):
    # API endpoint: /profile
    def post(self):
        response = {}
        decoded = self._token_decoded
        exptime =  datetime.datetime.utcfromtimestamp(decoded['exp'])
        ttl = (exptime - datetime.datetime.utcnow()).seconds
        response["status"] = "ok"
        response["message"] = "valid token"
        response["name"] = decoded["name"]
        response["username"] = decoded["username"]
        response["email"] = decoded["email"]
        response["ttl"] = ttl
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
        encoded = encode_info(name, username, email, envvars.JWT_TTL_SECONDS)


        response["status"] = "ok"
        response["message"] = "login"
        response["name"] = name
        response["email"] = email
        response["token"] = encoded.decode(encoding='UTF-8')


        # Store encrypted password in database for subsequent job requests
        ciphertext = jobutils.password_encrypt(passwd)
        response["status"] = JOBSDB.session_login(username, email, response["token"], ciphertext)

        self.write(json.dumps(response))

@authenticated
class JobHandler(BaseHandler):
    # API endpoint: /job/submit
    def put(self):
        body = {k: self.get_argument(k) for k in self.request.arguments}
        logger.info(body)
        st,msg,jobid = jobutils.submit_job(body)
        logger.info(msg)
        out = dict(status=st, message=msg, jobid=jobid)
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/delete
    def delete(self):
        username = self.getarg("username")
        job = self.getarg("job")
        jobid = self.getarg("jobid")
        conf = {"job": job}
        conf["namespace"] = jobutils.get_namespace()
        conf["job_name"] = jobutils.get_job_name(conf["job"], jobid, username)
        conf["cm_name"] = jobutils.get_job_configmap_name(conf["job"], jobid, username)
        kubejob.delete_job(conf)
        out = dict(msg="done")
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/status
    def post(self):
        username = self.getarg("username")
        job = self.getarg("job")
        jobid = self.getarg("jobid")
        conf = {"job": job}
        conf["namespace"] = jobutils.get_namespace()
        conf["job_name"] = jobutils.get_job_name(conf["job"], jobid, username)
        status,body = kubejob.status_job(conf)
        if status == "ok":
            out = dict(
                status=status,
                message="",
                active=body.active,
                succeeded=body.succeeded,
                failed=body.failed,
            )
        else:
            out = dict(
                status="error",
                message="Job {} id:{} not found".format(job, jobid),
            )
        self.write(json.dumps(out, indent=4))


# ## This is the one providing a list of hidden/allowed resources
# class InitHandler(BaseHandler):
#     # API endpoint: /init
#     def post(self):
#         cnx, cur = open_db_connection()
#         username = self.getarg("username")
#         logger.info(username)
#         t = cur.execute(
#             "select pages from access where username = '{}'".format(username))
#         d = t.fetchone()
#         close_db_connection(cnx, cur)
#         pages = []
#         if d is not None:
#             pages = d[0].replace(" ", "").split(",")
#         out = dict(access=pages)
#         self.write(json.dumps(out, indent=4))


@authenticated
class TestHandler(BaseHandler):
    # API endpoint: /test
    def post(self):
        username = self.getarg("username")
        response = {"username": username}
        response = {"token_decoded": self._token_decoded}
        self.write(json.dumps(response, indent=4))



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
        rowId = JOBSDB.validate_apitoken(apitoken)
        if isinstance(rowId, int):
            error_msg = JOBSDB.update_job_start(rowId)
            if error_msg is not None:
                logger.info(error_msg)


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
        rowId = JOBSDB.validate_apitoken(apitoken)
        if isinstance(rowId, int):
            error_msg = JOBSDB.update_job_complete(rowId)
            if error_msg is not None:
                logger.info(error_msg)


class DebugTrigger(BaseHandler):
    # API endpoint: /debug/trigger
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        if data["password"] == envvars.MYSQL_PASSWORD:
            rpdb.set_trace()


class TestConcurrency(BaseHandler):
    # API endpoint: /test/concurrency
    def post(self):
        try:
            data = json.loads(self.request.body.decode('utf-8'))
            if data["password"] == envvars.MYSQL_PASSWORD:
                tests.run_concurrency_tests()
        except:
            logger.info('Error decoding JSON data or invalid password')
            self.write({
                "status": "error",
                "reason": "Invalid JSON in HTTP request body or invalid password."
            })


def make_app(basePath=''):
    settings = {"debug": True}
    return tornado.web.Application(
        [
            (r"{}/job/status?".format(basePath), JobHandler),
            (r"{}/job/delete?".format(basePath), JobHandler),
            (r"{}/job/submit?".format(basePath), JobHandler),
            (r"{}/login/?".format(basePath), LoginHandler),
            (r"{}/profile/?".format(basePath), ProfileHandler),
            # (r"{}/init/?".format(basePath), InitHandler),
            (r"{}/test/?".format(basePath), TestHandler),
            (r"{}/job/complete?".format(basePath), JobComplete),
            (r"{}/job/start?".format(basePath), JobStart),
            (r"{}/test/concurrency?".format(basePath), TestConcurrency),
            (r"{}/debug/trigger?".format(basePath), DebugTrigger),
        ],
        **settings
    )


if __name__ == "__main__":

    if int(envvars.SERVICE_PORT):
        servicePort = int(envvars.SERVICE_PORT)
    else:
        servicePort = 8080
    if envvars.BASE_PATH == '' or envvars.BASE_PATH == '/' or not isinstance(envvars.BASE_PATH, str):
        basePath = ''
    else:
        basePath = envvars.BASE_PATH

    # Reset the database if DROP_TABLES is set.
    if envvars.DROP_TABLES == True:
        JOBSDB.reinitialize_tables()

    app = make_app(basePath=basePath)
    app.listen(servicePort)
    tornado.ioloop.IOLoop.current().start()
