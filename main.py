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
        response["lastname"] = decoded["lastname"]
        response["username"] = decoded["username"]
        response["email"] = decoded["email"]
        response["db"] = decoded["db"]
        response["roles"] = decoded["roles"]
        response["ttl"] = ttl
        self.flush()
        self.write(response)
        self.finish()
        return


@authenticated
class ProfileUpdateHandler(BaseHandler):
    # API endpoint: /profile/update/info
    def post(self):
        response = {}
        body = {k: self.get_argument(k) for k in self.request.arguments}
        # Enforce lowercase usernames
        username = body['username'].lower()
        first = body['firstname']
        last = body['lastname']
        email = body['email']
        # TODO: Allow users with "admin" role to update any user profile
        if username == self._token_decoded["username"]:
            status, msg = dbutils.update_info(username, first, last, email)
            response['status'] = status
            response['message'] = msg
        else:
            response['status'] = 'error'
            response['message'] = 'User info to update must belong to the authenticated user.'
        self.flush()
        self.write(response)
        self.finish()
        return


class ProfileUpdatePasswordHandler(BaseHandler):
    # API endpoint: /profile/update/password
    def post(self):
        response = {}
        body = {k: self.get_argument(k) for k in self.request.arguments}
        username = body['username'].lower()
        oldpwd = body['oldpwd']
        newpwd = body['newpwd']
        database = body['db']
        # TODO: Allow users with "admin" role to update any user profile
        if username == self._token_decoded["username"]:
            status, message = dbutils.change_credentials(username, oldpwd, newpwd, database)
            response['status'] = status
            response['message'] = message
        else:
            response['status'] = 'error'
            response['message'] = 'User info to update must belong to the authenticated user.'
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
        name, last, email = dbutils.get_basic_info(username)
        roles = JOBSDB.get_user_roles(username)
        encoded = encode_info(name, last, username, email, db, roles, envvars.JWT_TTL_SECONDS)


        response["status"] = "ok"
        response["message"] = "login"
        response["name"] = name
        response["lastname"] = last
        response["email"] = email
        response["db"] = db
        response["roles"] = roles
        response["token"] = encoded.decode(encoding='UTF-8')


        # Store encrypted password in database for subsequent job requests
        ciphertext = jobutils.password_encrypt(passwd)
        response["status"] = JOBSDB.session_login(username, response["token"], ciphertext)

        self.write(json.dumps(response))

@authenticated
class LogoutHandler(BaseHandler):
    # API endpoint: /logout
    def post(self):
        response = {}
        response["status"] = "ok"
        response["message"] = "logout {}".format(self._token_decoded["username"])
        response["status"] = JOBSDB.session_logout(self._token_decoded["username"])
        self.write(json.dumps(response))

@authenticated
class JobHandler(BaseHandler):
    # API endpoint: /job/submit
    def put(self):
        body = {k: self.get_argument(k) for k in self.request.arguments}
        # If username is not specified, assume it is the authenticated user
        try:
            username = body["username"].lower()
        except:
            username = self._token_decoded["username"]
        # TODO: Allow users with "admin" role to specify any username
        if username == self._token_decoded["username"]:
            status,message,jobid = jobutils.submit_job(body)
        else:
            status = 'error'
            message = 'Username specified must belong to the authenticated user.'
        logger.info(message)
        out = dict(status=status, message=message, jobid=jobid)
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/delete
    def delete(self):
        # If username is not specified, assume it is the authenticated user
        try:
            username = self.getarg("username").lower()
        except:
            username = self._token_decoded["username"]
        # TODO: Allow users with "admin" role to specify any username
        if username == self._token_decoded["username"]:
            job = self.getarg("job")
            # TODO: Allow specifying jobid "all" to delete all of user's jobs
            jobid = self.getarg("jobid")
            conf = {"job": job}
            conf["namespace"] = jobutils.get_namespace()
            conf["job_name"] = jobutils.get_job_name(conf["job"], jobid, username)
            conf["cm_name"] = jobutils.get_job_configmap_name(conf["job"], jobid, username)
            kubejob.delete_job(conf)
            status = 'ok'
            message = 'Job "{}" deleted.'.format(jobid)
        else:
            status = 'error'
            message = 'Username specified must be the authenticated user.'
        out = dict(status=status, message=message, jobid=jobid)
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/status
    def post(self):
        # TODO: Use role-based access control to allow a username parameter different
        #       from the authenticated user. For example, a user with role "admin" could
        #       obtain job status for any user.
        username = self._token_decoded["username"]
        job_id = self.getarg("job-id")
        job_info_list, status, msg = JOBSDB.job_status(username, job_id)
        out = dict(
            status=status,
            message=msg,
            jobs=job_info_list
        )
        # The datetime type is not JSON serializable, so convert to string
        def myconverter(o):
            if isinstance(o, datetime.datetime):
                return o.__str__()
        self.write(json.dumps(out, indent=4, default = myconverter))


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
        error_msg = JOBSDB.update_job_start(apitoken)
        if error_msg is not None:
            logger.error(error_msg)


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
        error_msg = None
        try:
            error_msg = JOBSDB.update_job_complete(apitoken, data["response"])
        except:
            pass
        if error_msg is not None:
            logger.error(error_msg)


class DebugTrigger(BaseHandler):
    # API endpoint: /dev/debug/trigger
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        if data["password"] == envvars.MYSQL_PASSWORD:
            rpdb.set_trace()


class DbWipe(BaseHandler):
    # API endpoint: /dev/db/wipe
    def post(self):
        body = {k: self.get_argument(k) for k in self.request.arguments}
        try:
            # Reset the database if DROP_TABLES is set and database password is valid.
            if body["password"] == envvars.MYSQL_PASSWORD and envvars.DROP_TABLES == True:
                JOBSDB.reinitialize_tables()
                # TODO: We might wish to verify if tables were actually cleared and return error if not.
                self.write({
                    "status": "ok",
                    "msg": ""
                })
                return
            self.write({
                "status": "error",
                "msg": "Invalid password or DROP_TABLES environment variable not true."
            })
        except:
            logger.info('Error decoding JSON data or invalid password')
            self.write({
                "status": "error",
                "msg": "Invalid JSON in HTTP request body."
            })


def make_app(basePath=''):
    settings = {"debug": True}
    return tornado.web.Application(
        [
            ## JOBS Endpoints
            (r"{}/job/status?".format(basePath), JobHandler),
            (r"{}/job/delete?".format(basePath), JobHandler),
            (r"{}/job/submit?".format(basePath), JobHandler),
            (r"{}/job/complete?".format(basePath), JobComplete),
            (r"{}/job/start?".format(basePath), JobStart),
            ## Profile Endpoints
            (r"{}/login/?".format(basePath), LoginHandler),
            (r"{}/profile/?".format(basePath), ProfileHandler),
            (r"{}/profile/update/info?".format(basePath), ProfileUpdateHandler),
            (r"{}/profile/update/password?".format(basePath), ProfileUpdatePasswordHandler),
            (r"{}/logout/?".format(basePath), LogoutHandler),
            ## Test Endpoints
            # (r"{}/init/?".format(basePath), InitHandler),
            (r"{}/dev/debug/trigger?".format(basePath), DebugTrigger),
            (r"{}/dev/db/wipe?".format(basePath), DbWipe),
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

    # Reset the database using the API endpoint /dev/db/wipe
    # if envvars.DROP_TABLES == True:
    #     JOBSDB.reinitialize_tables()

    app = make_app(basePath=basePath)
    app.listen(servicePort)
    logger.info('Running at localhost:{}{}'.format(servicePort,basePath))
    tornado.ioloop.IOLoop.current().start()
