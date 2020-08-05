import rpdb
import tornado.ioloop
import tornado.web
import tornado
import json
import yaml
import datetime
import logging
import kubejob
import dbutils
from jwtutils import authenticated
from jwtutils import encode_info
import envvars
import jobutils
import time
from io import StringIO
from pandas import read_csv, DataFrame
import os
import easyaccess as ea
import jira.client
import base64
from jinja2 import Template
import email_utils
import jlab
import uuid
import shutil

STATUS_OK = 'ok'
STATUS_ERROR = 'error'

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

# Initialize global Jira API object
#
# Obtain the Jira API auth credentials from the mounted secret
jira_access_file = os.path.join(
    os.path.dirname(__file__),
    "jira_access.yaml"
)
with open(jira_access_file, 'r') as cfile:
    conf = yaml.load(cfile)['jira']
# Initialize Jira API object
JIRA_API = jira.client.JIRA(
    options={'server': 'https://opensource.ncsa.illinois.edu/jira'},
    basic_auth=(
        base64.b64decode(conf['uu']).decode().strip(),
        base64.b64decode(conf['pp']).decode().strip()
    )
)

# The datetime type is not JSON serializable, so convert to string
def json_converter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()


def webcron(cls_handler):
    def wrap_execute(handler_execute):
        def run_cron(handler, kwargs):
            # logger.info('Running webcron...')
            cronjobs, error_msg = JOBSDB.cron_get_all()
            if error_msg != '':
                cronjobs = []
                logger.error(error_msg)
            try:
                current_time = datetime.datetime.utcnow()
                for cronjob in cronjobs:
                    # Period is an integer in units of minutes
                    if not cronjob['last_run'] or (current_time - cronjob['last_run']).seconds/60 >= cronjob['period']:
                        # Time to run the cron job again
                        logger.info('Running cron job "{}" at "{}".'.format(cronjob['name'], current_time))
                        if cronjob['name'] == 'jupyter_prune':
                            # Get list of users in Jupyter role
                            jupyter_users = JOBSDB.get_role_user_list('jupyter')
                            pruned, error_msg = jlab.prune(jupyter_users, current_time)
                            logger.info('Pruned Jupyter servers for users: {}'.format(pruned))
                        # elif cronjob['name'] == 'another_task':
                            # et cetera ...
                        # Update the last_run time with the current time
                        JOBSDB.cron_update_run_time(cronjob['name'], current_time)
            except Exception as e:
                error_msg = str(e).strip()
                logger.error(error_msg)
            return

        def _execute(self, transforms, *args, **kwargs):
            run_cron(self, kwargs)
            return handler_execute(self, transforms, *args, **kwargs)
        return _execute
    cls_handler._execute = wrap_execute(cls_handler._execute)
    return cls_handler


@webcron
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
        try: 
            prefs, error_msg = JOBSDB.get_user_preference('all', decoded["username"])
            if error_msg != '':
                logger.error(error_msg)
                prefs = {}
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
            prefs = {}
        response["preferences"] = prefs
        response["ttl"] = ttl
        response["new_token"] = self._token_encoded
        self.flush()
        self.write(response)
        self.finish()
        return


@authenticated
class ProfileUpdateHandler(BaseHandler):
    # API endpoint: /profile/update/info
    def post(self):
        response = {}
        response["new_token"] = self._token_encoded
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


@authenticated
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
        try: 
            prefs, error_msg = JOBSDB.get_user_preference('all', username)
            if error_msg != '':
                logger.error(error_msg)
                prefs = {}
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
            prefs = {}
        response["preferences"] = prefs


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
        response["new_token"] = self._token_encoded
        self.write(json.dumps(response))

@authenticated
class JobHandler(BaseHandler):
    # API endpoint: /job/submit
    def put(self):
        try:
            params = json.loads(self.request.body.decode('utf-8'))
        except:
            params = {k: self.get_argument(k) for k in self.request.arguments}
        # If username is not specified, assume it is the authenticated user
        try:
            username = params["username"].lower()
        except:
            username = self._token_decoded["username"]
        # If the database is not specified in the request, assume the database to
        # use is the one encoded in the authentication token
        if 'db' not in params or not isinstance(params['db'], str) or len(params['db']) < 1:
            params["db"] = self._token_decoded["db"]
        try:
            params["user_agent"] = self.request.headers["User-Agent"]
        except:
            params["user_agent"] = ''
        jobid = ''
        try:
            # TODO: Allow users with "admin" role to specify any username
            if username == self._token_decoded["username"]:
                status,message,jobid = jobutils.submit_job(params)
            else:
                status = STATUS_ERROR
                message = 'Username specified must belong to the authenticated user.'
                logger.error(message)
        except Exception as e:
            status = STATUS_ERROR
            message = str(e).strip()
            logger.error(message)
        out = {
            'status': status,
            'message': message,
            'jobid': jobid,
            'new_token': self._token_encoded
        }
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/delete
    def delete(self):
        status = STATUS_OK
        message = ''
        # If username is not specified, assume it is the authenticated user
        try:
            params = json.loads(self.request.body.decode('utf-8'))
        except:
            params = {k: self.get_argument(k) for k in self.request.arguments}

        try:
            if 'username' in params and isinstance(params['username'], str):
                username = params['username'].lower()
            else:
                username = self._token_decoded["username"]
        except:
            status = STATUS_ERROR
            message = 'Invalid username specified.'
            out = {
                'status': status,
                'message': message,
                'new_token': self._token_encoded
            }
            self.write(json.dumps(out, indent=4))

        job_ids = []
        if isinstance(params['job-id'], str):
            job_ids.append(params['job-id'])
        elif isinstance(params['job-id'], list):
            job_ids = params['job-id']
        else:
            status = STATUS_ERROR
            message = 'job-id must be a single job ID value or an array of job IDs'
            out = {
                'status': status,
                'message': message,
                'new_token': self._token_encoded
            }
            self.write(json.dumps(out, indent=4))

        for job_id in job_ids:
            try:
                # Determine the type of the job to delete
                job_info_list, request_status, status_msg = JOBSDB.job_status(username, job_id)
                if request_status == STATUS_ERROR:
                    status = STATUS_ERROR
                    message = status_msg
                else:
                    job_type = job_info_list[0]['job_type']
            except:
                status = STATUS_ERROR
                message = 'Invalid username or job ID specified.'
                out = {
                    'status': status,
                    'message': message,
                    'new_token': self._token_encoded
                }
                self.write(json.dumps(out, indent=4))

            # TODO: Allow users with "admin" role to specify any username
            if status == STATUS_OK:
                # TODO: Allow specifying job-id "all" to delete all of user's jobs
                if username == self._token_decoded["username"]:
                    # Delete the k8s Job if it is still running
                    conf = {}
                    conf["job_type"] = job_type
                    conf["namespace"] = jobutils.get_namespace()
                    conf["job_name"] = jobutils.get_job_name(job_type, job_id, username)
                    conf["job_id"] = job_id
                    conf["cm_name"] = jobutils.get_job_configmap_name(job_type, job_id, username)
                    kubejob.delete_job(conf)
                    # Delete the job files on disk
                    status, message = JOBSDB.delete_job_files(job_id, username)
                    # Mark the job deleted in the JobHandler database
                    if status == STATUS_OK:
                        message = JOBSDB.mark_job_deleted(job_id)
                        if message != '':
                            status = STATUS_ERROR
                            logger.error('utility job submit failed: "{}"'.format(message))
                        else:
                            message = 'Job "{}" deleted.'.format(job_id)
                else:
                    status = STATUS_ERROR
                    message = 'Username specified must be the authenticated user.'
                    out = {
                        'status': status,
                        'message': message,
                        'new_token': self._token_encoded
                    }
                    self.write(json.dumps(out, indent=4))
        out = {
            'status': status,
            'message': message,
            'new_token': self._token_encoded
        }
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/status
    def post(self):
        # TODO: Use role-based access control to allow a username parameter different
        #       from the authenticated user. For example, a user with role "admin" could
        #       obtain job status for any user.
        username = self._token_decoded["username"]
        job_id = self.getarg("job-id")
        job_info_list, status, message = JOBSDB.job_status(username, job_id)
        out = {
            'status': status,
            'message': message,
            'jobs': job_info_list,
            'new_token': self._token_encoded
        }
        self.write(json.dumps(out, indent=4, default = json_converter))


class JobStart(BaseHandler):
    # API endpoint: /job/start
    def post(self):
        try:
            data = json.loads(self.request.body.decode('utf-8'))
            logger.info('/job/start data: {}'.format(json.dumps(data)))
        except:
            logger.info('Error decoding JSON data')
            self.write({
                "status": STATUS_ERROR,
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
                "status": STATUS_ERROR,
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


@authenticated
class JobRename(BaseHandler):
    # API endpoint: /job/rename
    def post(self):
        status = STATUS_OK
        message = ''
        # If username is not specified, assume it is the authenticated user
        try:
            params = json.loads(self.request.body.decode('utf-8'))
        except:
            params = {k: self.get_argument(k) for k in self.request.arguments}
        try:
            if 'username' in params and isinstance(params['username'], str):
                username = params['username'].lower()
            else:
                username = self._token_decoded["username"]
            # Get job ID of job to delete
            job_id = params['job-id']
            # Determine the type of the job to delete
            job_info_list, request_status, status_msg = JOBSDB.job_status(username, job_id)
            if request_status == STATUS_ERROR:
                status = STATUS_ERROR
                message = status_msg
            else:
                job_name = job_info_list[0]['job_name']
        except:
            status = STATUS_ERROR
            message = 'Invalid username or job ID specified.'

        # TODO: Allow users with "admin" role to specify any username
        if status == STATUS_OK and job_name != params['job-name']:
            if username == self._token_decoded["username"]:
                message = JOBSDB.rename_job(job_id, params['job-name'])
                if message != '':
                    status = STATUS_ERROR
                else:
                    message = 'Job "{}" renamed to {}.'.format(job_id, params['job-name'])
            else:
                status = STATUS_ERROR
                message = 'Username specified must be the authenticated user.'
        out = {
        'status': status,
        'message': message,
        'new_token': self._token_encoded
        }
        self.write(json.dumps(out, indent=4))


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
                    "status": STATUS_OK,
                    "msg": ""
                })
                return
            self.write({
                "status": STATUS_ERROR,
                "msg": "Invalid password or DROP_TABLES environment variable not true."
            })
        except:
            logger.info('Error decoding JSON data or invalid password')
            self.write({
                "status": STATUS_ERROR,
                "msg": "Invalid JSON in HTTP request body."
            })


class ValidateCsvHandler(BaseHandler):
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        tempCsvFile = '.temp.csv'
        try:

            parsedData = read_csv(StringIO(data['csvText']), dtype={
                'RA': float,
                'DEC': float,
                'COADD_OBJECT_ID': int,
                'XSIZE': float,
                'YSIZE': float
            })

            if all(k in parsedData for k in ('RA','DEC','XSIZE','YSIZE')):
                df = DataFrame(parsedData, columns=['RA','DEC','XSIZE','YSIZE'])
                df['XSIZE'] = df['XSIZE'].map(lambda x: '%.2f' % x)
                df['YSIZE'] = df['YSIZE'].map(lambda x: '%.2f' % x)
                df.to_csv(tempCsvFile, index=False, float_format='%.12f')
                type = "coords"
            elif all(k in parsedData for k in ('RA','DEC')):
                df = DataFrame(parsedData, columns=['RA','DEC'])
                df.to_csv(tempCsvFile, index=False, float_format='%.12f')
                type = "coords"
            elif all(k in parsedData for k in ('COADD_OBJECT_ID','XSIZE','YSIZE')):
                df = DataFrame(parsedData, columns=['COADD_OBJECT_ID','XSIZE','YSIZE'])
                df.to_csv(tempCsvFile, index=False, float_format='%.2f')
                type = "id"
            elif 'COADD_OBJECT_ID' in parsedData:
                df = DataFrame(parsedData, columns=['COADD_OBJECT_ID'])
                df.to_csv(tempCsvFile, index=False, float_format='%.2f')
                type = "id"
            else:
                logger.info('CSV header must have RA/DEC or COADD_OBJECT_ID')
                self.write({
                    "status": STATUS_ERROR,
                    "msg": 'CSV header must have RA/DEC or COADD_OBJECT_ID'
                })
                return

            with open(tempCsvFile) as f:
                processedCsvText = f.read()
            os.remove(tempCsvFile)
            self.write({
                "status": STATUS_OK,
                "msg": "",
                "csv": processedCsvText,
                "type": type
            })
        except:
            logger.info('Error decoding JSON data')
            self.write({
                "status": STATUS_ERROR,
                "msg": "Invalid JSON in HTTP request body."
            })


@authenticated
class CheckQuerySyntaxHandler(BaseHandler):
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": "",
            "valid": True
        }
        username = self._token_decoded["username"]
        password = JOBSDB.get_password(username)
        db = self._token_decoded["db"]
        try:
            query = data['query']
            try:
                connection = ea.connect(db, user=username, passwd=password)
                cursor = connection.cursor()
            except Exception as e:
                response['status'] = STATUS_ERROR
                response['msg'] = str(e).strip()
            try:
                cursor.parse(query.encode())
            except Exception as e:
                # response['status'] = STATUS_ERROR
                response['msg'] = str(e).strip()
                response['valid'] = False
            cursor.close()
            connection.close()
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class ListUserRolesHandler(BaseHandler):
    def post(self):
        # data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": "",
            'users': {}
        }
        roles = self._token_decoded["roles"]
        try:
            if 'admin' in roles:
                # Sync status of help request table records with their Jira issues
                response['msg'] = JOBSDB.sync_help_requests_with_jira()
                # Compile user list with role and help request data
                response['users'] = JOBSDB.get_all_user_roles_and_help_requests()
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied: You must be an admin."
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class NotificationsCreateHandler(BaseHandler):
    # Messages are created by admins using the PUT request type
    def put(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        roles = self._token_decoded["roles"]
        try:
            if 'admin' in roles:
                # If the roles array is empty or missing, include the default role
                if 'roles' not in data or data['roles'] == []:
                    data['roles'] = ['default']
                # Insert message into database table
                error_msg = JOBSDB.create_notification(data['title'], data['body'], data['roles'], datetime.datetime.utcnow())
                if error_msg != '':
                    response['status'] = STATUS_ERROR
                    response['msg'] = error_msg
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied: You must be an admin."
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class NotificationsDeleteHandler(BaseHandler):
    def post(self):
        error_msg = ''
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        roles = self._token_decoded["roles"]
        try:
            if 'admin' in roles:
                # Delete message from database table
                error_msg = JOBSDB.delete_notification(data['message-id'])
                if error_msg != '':
                    response['status'] = STATUS_ERROR
                    response['msg'] = error_msg
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied: You must be an admin."
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class NotificationsEditHandler(BaseHandler):
    def post(self):
        error_msg = ''
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        roles = self._token_decoded["roles"]
        try:
            if 'admin' in roles:
                # Delete message from database table
                error_msg = JOBSDB.edit_notification(data['id'], data['title'], data['body'], data['roles'])
                if error_msg != '':
                    response['status'] = STATUS_ERROR
                    response['msg'] = error_msg
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied: You must be an admin."
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class JupyterLabPruneHandler(BaseHandler):
    def post(self):
        error_msg = ''
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        roles = self._token_decoded["roles"]
        try:
            if 'admin' in roles:
                current_time = datetime.datetime.utcnow()
                jupyter_users = JOBSDB.get_role_user_list('jupyter')
                pruned, error_msg = jlab.prune(jupyter_users, current_time)
                logger.info('Pruned Jupyter servers for users: {}'.format(pruned))
                if error_msg != '':
                    response['status'] = STATUS_ERROR
                    response['msg'] = error_msg
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied: You must be an admin."
        except:
            logger.info('Error pruning JupyterLab servers.')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class JupyterLabCreateHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'token': '',
            'url': ''
        }
        roles = self._token_decoded["roles"]
        try:
            if any(role in roles for role in ('jupyter', 'admin')):
                username = self._token_decoded["username"]
                response['token'] = str(uuid.uuid4()).replace("-", "")
                base_path = '/jlab/{}'.format(username)
                response['url'] = '{}{}?token={}'.format(envvars.FRONTEND_BASE_URL, base_path, response['token'])
                error_msg = jlab.create(username, base_path, response['token'])
                if error_msg != '':
                    response['status'] = STATUS_ERROR
                    response['msg'] = error_msg
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied."
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(response)


@authenticated
class JupyterLabDeleteHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        roles = self._token_decoded["roles"]
        try:
            if any(role in roles for role in ('jupyter', 'admin')):
                username = self._token_decoded["username"]
                error_msg = jlab.delete(username)
                if error_msg != '':
                    response['status'] = STATUS_ERROR
                    response['msg'] = error_msg
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied."
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(response)


@authenticated
class JupyterLabStatusHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'ready_replicas': -1,
            'unavailable_replicas': -1,
            'token': '',
            'creation_timestamp': '',
            'latest_condition_type': 'Unknown',
        }
        roles = self._token_decoded["roles"]
        try:
            if any(role in roles for role in ('jupyter', 'admin')):
                username = self._token_decoded["username"]
                stat, error_msg = jlab.status(username)
                if error_msg != '':
                    response['status'] = STATUS_ERROR
                    response['msg'] = error_msg
                response['ready_replicas'] = stat['ready_replicas']
                response['unavailable_replicas'] = stat['unavailable_replicas']
                response['latest_condition_type'] = stat['latest_condition_type']
                response['token'] = stat['token']
                response['creation_timestamp'] = stat['creation_timestamp']
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied."
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(json.dumps(response, indent=4, default = json_converter))


@authenticated
class JupyterLabFileListHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'folders': []
        }
        roles = self._token_decoded["roles"]
        try:
            if any(role in roles for role in ('jupyter', 'admin')):
                username = self._token_decoded["username"]
                jupyter_dir = os.path.join('/jobfiles', username, 'jupyter/public')
                logger.info(jupyter_dir)
                jupyter_dirs = []
                with os.scandir(jupyter_dir) as it:
                    for entry in it:
                        if not entry.name.startswith('.') and entry.is_dir():
                            mod_timestamp = datetime.datetime.fromtimestamp(entry.stat().st_mtime)
                            logger.info('{}: {}'.format(entry.name, mod_timestamp))
                            jupyter_dirs.append({
                                'directory': entry.name,
                                'time': mod_timestamp
                            })
                response['folders'] = jupyter_dirs
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied."
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(json.dumps(response, indent=4, default = json_converter))


@authenticated
class JupyterLabFileDeleteHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        data = json.loads(self.request.body.decode('utf-8'))
        roles = self._token_decoded["roles"]
        try:
            if any(role in roles for role in ('jupyter', 'admin')):
                username = self._token_decoded["username"]
                jupyter_dir = os.path.join('/jobfiles', username, 'jupyter/public', data['token'])

                logger.info(jupyter_dir)
                if os.path.isdir(jupyter_dir):
                    shutil.rmtree(jupyter_dir)
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied."
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(json.dumps(response, indent=4, default = json_converter))


@authenticated
class NotificationsFetchHandler(BaseHandler):
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": "",
            'messages': []
        }
        # Get roles from token and avoid a database query
        roles = self._token_decoded["roles"]
        username = self._token_decoded["username"]
        try:
            # Validate the API request parameters
            message = data['message']
            if not isinstance(message, str) or message not in ['all', 'new']:
                response['status'] = STATUS_ERROR
                response['msg'] = 'Parameter "message" must be a message ID or the word "all" or "new".'
            else:
                # Query database for requested messages
                response['messages'], error_msg = JOBSDB.get_notifications(message, username, roles)
                if error_msg != '':
                    response['status'] = STATUS_ERROR
                    response['msg'] = error_msg
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(json.dumps(response, indent=4, default = json_converter))


@authenticated
class NotificationsMarkHandler(BaseHandler):
    # Messages are marked read by users using the POST request type
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        username = self._token_decoded["username"]
        try:
            error_msg = JOBSDB.mark_notification_read(data['message-id'], username)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class UserPreferencesHandler(BaseHandler):
    def put(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        username = self._token_decoded["username"]
        try:
            error_msg = JOBSDB.set_user_preference(data['pref'], data['value'], username)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class HelpFormHandler(BaseHandler):
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        data['username'] = self._token_decoded["username"]
        # TODO: Consider reconciling any differences between the
        # user profile data in the auth token with the custom
        # name and email provided by the help form
        try:
            email = data['email']
            firstname = data['firstname']
            lastname = data['lastname']
            topics = ', \n'.join(data['topics'])
            message = data['message']
            othertopic = data['othertopic']
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
            self.write(response)
            return
        # Generate a new Jira ticket using the Jira API
        try:
            # Construct Jira issue body from template file
            jiraIssueTemplateFile = os.path.join(
                os.path.dirname(__file__),
                "jira_issue.tpl"
            )
            with open(jiraIssueTemplateFile) as f:
                templateText = f.read()
            body = Template(templateText).render(
                email=email,
                firstname=firstname,
                lastname=lastname,
                topics=topics,
                message=message,
                othertopic=othertopic
            )
            issue = {
                'project' : {'key': 'DESLABS'},
                'issuetype': {'name': 'Task'},
                'summary': 'DESaccess alpha release help request ({})'.format(data['username']),
                'description' : body,
                #'reporter' : {'name': 'desdm-wufoo'},
            }
            new_jira_issue = JIRA_API.create_issue(fields=issue)
            data['jira_issue_number'] = '{}'.format(new_jira_issue)
            response['msg'] = 'Jira issue created: {}'.format(data['jira_issue_number'])
            try:
                # Send notification email to user and to admins via list
                # recipients, error_msg = JOBSDB.get_admin_emails()
                error_msg = ''
                recipients = ['desaccess-admins@lists.ncsa.illinois.edu', email]
                if error_msg == '':
                    email_utils.help_request_notification(data['username'], recipients, data['jira_issue_number'], body)
                else:
                    logger.error('Error sending notification email to admins ({}):\n{}'.format(data['jira_issue_number'], error_msg))
            except:
                logger.error('Error sending notification email to admins')
        except:
            response['status'] = STATUS_ERROR
            response['msg'] = "Error while creating Jira issue"
            logger.error('{}:\n{}'.format(response['msg'], issue))
            self.write(response)
            return
        # Store the help request information in the database
        try:
            response['msg'] = JOBSDB.process_help_request(data)
            if response['msg'] != '':
                response['status'] = STATUS_ERROR
                self.write(response)
                return
        except:
            logger.info('Error adding record to help table in DB')
            response['status'] = STATUS_ERROR
            response['msg'] = "Error inserting help request record into database table."

        self.write(response)


@authenticated
class UpdateUserRolesHandler(BaseHandler):
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        roles = self._token_decoded["roles"]
        try:
            if 'admin' in roles:
                response['msg'] = JOBSDB.update_user_roles(data['username'], data['new_roles'])
                if response['msg'] != '':
                    response['status'] = STATUS_ERROR
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied: You must be an admin."
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class SetUserRolesHandler(BaseHandler):
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        roles = self._token_decoded["roles"]
        try:
            if 'admin' in roles:
                response['msg'] = JOBSDB.set_user_roles(data['username'], data['roles'])
                if response['msg'] != '':
                    response['status'] = STATUS_ERROR
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied: You must be an admin."
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class ResetUserRoleHandler(BaseHandler):
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        roles = self._token_decoded["roles"]
        try:
            if 'admin' in roles:
                response['msg'] = JOBSDB.reset_user_roles(data['username'])
                if response['msg'] != '':
                    response['status'] = STATUS_ERROR
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied: You must be an admin."
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
class ListUsersHandler(BaseHandler):
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        response = {
            "status": STATUS_OK,
            "msg": "",
            "users": {}
        }
        roles = self._token_decoded["roles"]
        try:
            if 'admin' in roles:
                if 'username' in data:
                    if data['username'] == 'all':
                        response['users'] = dbutils.list_all_users()
                    else:
                        response['users'] = dbutils.get_basic_info(data['username'])
                else:
                    response['status'] = STATUS_ERROR
                    response['msg'] = "Parameter username must be specified. To list all users use value \"all\""
            else:
                response['status'] = STATUS_ERROR
                response['msg'] = "Permission denied: You must be an admin."
        except:
            logger.info('Error decoding JSON data')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


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
            (r"{}/job/rename?".format(basePath), JobRename),
            ## Profile Endpoints
            (r"{}/login/?".format(basePath), LoginHandler),
            (r"{}/profile/?".format(basePath), ProfileHandler),
            (r"{}/profile/update/info?".format(basePath), ProfileUpdateHandler),
            (r"{}/profile/update/password?".format(basePath), ProfileUpdatePasswordHandler),
            # TODO: Consider replacing user add/delete/update handlers with single handler using request types PUT/DELETE/POST
            (r"{}/user/role/update?".format(basePath), UpdateUserRolesHandler),
            (r"{}/user/role/add?".format(basePath), SetUserRolesHandler),
            (r"{}/user/role/reset?".format(basePath), ResetUserRoleHandler),
            (r"{}/user/role/list?".format(basePath), ListUserRolesHandler),
            (r"{}/user/list?".format(basePath), ListUsersHandler),
            (r"{}/user/preference?".format(basePath), UserPreferencesHandler),
            (r"{}/logout/?".format(basePath), LogoutHandler),
            (r"{}/page/cutout/csv/validate/?".format(basePath), ValidateCsvHandler),
            (r"{}/page/db-access/check/?".format(basePath), CheckQuerySyntaxHandler),
            (r"{}/page/help/form/?".format(basePath), HelpFormHandler),
            (r"{}/notifications/create/?".format(basePath), NotificationsCreateHandler),
            (r"{}/notifications/fetch/?".format(basePath), NotificationsFetchHandler),
            (r"{}/notifications/mark/?".format(basePath), NotificationsMarkHandler),
            (r"{}/notifications/delete/?".format(basePath), NotificationsDeleteHandler),
            (r"{}/notifications/edit/?".format(basePath), NotificationsEditHandler),
            (r"{}/jlab/create/?".format(basePath), JupyterLabCreateHandler),
            (r"{}/jlab/delete/?".format(basePath), JupyterLabDeleteHandler),
            (r"{}/jlab/status/?".format(basePath), JupyterLabStatusHandler),
            (r"{}/jlab/prune/?".format(basePath), JupyterLabPruneHandler),
            (r"{}/jlab/files/list?".format(basePath), JupyterLabFileListHandler),
            (r"{}/jlab/files/delete?".format(basePath), JupyterLabFileDeleteHandler),
            ## Test Endpoints
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

    # Apply any database updates
    try:
        # Wait for database to come online if it is still starting
        waiting_for_db = True
        while waiting_for_db:
            try:
                JOBSDB.open_db_connection()
                waiting_for_db = False
                JOBSDB.close_db_connection()
            except:
                logger.error('Unable to connect to database. Waiting to try again...')
                time.sleep(5.0)
        # Create/update database tables
        JOBSDB.update_db_tables()
        # Initialize database
        JOBSDB.init_db()
    except Exception as e:
        logger.error(str(e).strip())

    app = make_app(basePath=basePath)
    app.listen(servicePort)
    logger.info('Running at localhost:{}{}'.format(servicePort,basePath))
    tornado.ioloop.IOLoop.current().start()
