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
from jwtutils import validate_token
import envvars
import jobutils
import time
import os
import easyaccess as ea
import jira.client
import base64
from jinja2 import Template
import email_utils
import jlab
import ip
import uuid
import shutil
import re
from des_tasks.cutout.worker.bulkthumbs import validate_positions_table as validate_cutout_positions_table

STATUS_OK = 'ok'
STATUS_ERROR = 'error'

PASSWORD_REGEX = r'^[A-Za-z]+[A-Za-z0-9]{10,40}'
PASSWORD_VALIDITY_MESSAGE = "Password must be between 10 and 30 characters long and contain only characters A-Z, a-z, 0-9, '.', '?', '!', '-'"

ALLOWED_ROLE_LIST = envvars.ALLOWED_ROLE_LIST.split(',')

# Get global instance of the job handler database interface
JOBSDB = jobutils.JobsDb(
    mysql_host=envvars.MYSQL_HOST,
    mysql_user=envvars.MYSQL_USER,
    mysql_password=envvars.MYSQL_PASSWORD,
    mysql_database=envvars.MYSQL_DATABASE
)

# Configure logging
#
# Set logging format and basic config
log_format = "%(asctime)s  %(name)8s  %(levelname)5s  %(message)s"
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.FileHandler("test.log"), logging.StreamHandler()],
    format=log_format,
)
# Create a logging filter to protect user passwords and reduce clutter.
class TornadoLogFilter(logging.Filter):
    def filter(self, record):
        print(record.getMessage())
        if record.getMessage().find('api/login') > -1 or record.getMessage().find('api/job/status') > -1:
            ret_val = 0
        else:
            ret_val = 1
        return ret_val
logging.getLogger("tornado.access").addFilter(TornadoLogFilter())
# Define the logger for this module
logger = logging.getLogger("main")
logger.setLevel(logging.INFO)

try:
    # Initialize global Jira API object
    #
    # Obtain the Jira API auth credentials from the mounted secret
    jira_access_file = os.path.join(
        os.path.dirname(__file__),
        "jira_access.yaml"
    )
    with open(jira_access_file, 'r') as cfile:
        conf = yaml.load(cfile, Loader=yaml.FullLoader)['jira']
    # Initialize Jira API object
    JIRA_API = jira.client.JIRA(
        options={'server': 'https://opensource.ncsa.illinois.edu/jira'},
        basic_auth=(
            base64.b64decode(conf['uu']).decode().strip(),
            base64.b64decode(conf['pp']).decode().strip()
        )
    )
except:
    JIRA_API = None

# Initialize the Oracle database user manager and set email list address
if envvars.DESACCESS_INTERFACE == 'public':
    USER_DB_MANAGER = dbutils.dbConfig(envvars.ORACLE_PUB, envvars.ORACLE_PUB_DBS)
    EMAIL_LIST_ADDRESS = envvars.DESACCESS_PUBLIC_EMAILS
else:
    USER_DB_MANAGER = dbutils.dbConfig(envvars.ORACLE_PRV, envvars.ORACLE_PRV_DBS)
    EMAIL_LIST_ADDRESS = envvars.DESACCESS_PRIVATE_EMAILS

# The datetime type is not JSON serializable, so convert to string
def json_converter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()

# The @analytics decorator captures usage statistics
def analytics(cls_handler):
    def wrap_execute(handler_execute):
        def wrapper(handler, kwargs):
            current_time = datetime.datetime.utcnow()
            try:
                request_path = handler.request.path
            except:
                request_path = ''
            try:
                user_agent = handler.request.headers["User-Agent"]
            except:
                user_agent = ''
            try:
                remote_ip = handler.request.remote_ip
            except:
                remote_ip = ''
            try:
                status, msg = JOBSDB.analytics_record_api(request_path, current_time, user_agent, remote_ip)
                if status != STATUS_OK:
                    error_msg = msg
            except Exception as e:
                error_msg = str(e).strip()
                logger.error(error_msg)
            return

        def _execute(self, transforms, *args, **kwargs):
            wrapper(self, kwargs)
            return handler_execute(self, transforms, *args, **kwargs)
        return _execute
    cls_handler._execute = wrap_execute(cls_handler._execute)
    return cls_handler


def webcron_jupyter_prune(current_time=None):
    status = STATUS_OK
    msg = ''
    try:
        if not current_time:
            current_time = datetime.datetime.utcnow()
        # Get list of users in Jupyter role
        jupyter_users = JOBSDB.get_role_user_list('jupyter')
        pruned, msg = jlab.prune(jupyter_users, current_time)
        logger.info('Pruned Jupyter servers for users: {}'.format(pruned))
    except Exception as e:
        status = STATUS_ERROR
        msg = str(e).strip()
        logger.error(msg)
    return status, msg


def webcron_refresh_database_table_cache():
    status = STATUS_OK
    msg = ''
    # Refresh the cache of DES database tables and their schemas
    try:
        status, msg = USER_DB_MANAGER.refresh_table_cache()
        if status != STATUS_OK:
            msg = 'webcron refresh_database_table_cache error: {}'.format(msg)
            logger.error(msg)
        else:
            logger.info('Refreshed the cache of DES database tables and their schemas.')
    except Exception as e:
        status = STATUS_ERROR
        msg = str(e).strip()
        logger.error(msg)
    return status, msg


def webcron_prune_job_files(job_ttl=envvars.DESACCESS_JOB_FILES_LIFETIME, job_warning_period=envvars.DESACCESS_JOB_FILES_WARNING_PERIOD, current_time=None):
    status = STATUS_OK
    msg = ''
    # Delete job files older than the set lifetime. Send warning to users whose jobs are approaching their expiration.
    try:
        if not current_time:
            current_time = datetime.datetime.utcnow()
        status, msg = JOBSDB.prune_job_files(USER_DB_MANAGER, job_ttl, job_warning_period, current_time)
        if status != STATUS_OK:
            msg = 'webcron webcron_prune_job_files error: {}'.format(msg)
            logger.error(msg)
        else:
            logger.info('Pruned job files.')
    except Exception as e:
        status = STATUS_ERROR
        msg = str(e).strip()
        logger.error(msg)
    return status, msg


def webcron_sync_email_list():
    status = STATUS_OK
    msg = ''
    # Sync the current list of public DESaccess users to the remote data source for the announcement email list
    all_users = None
    list_file = '/email_list/desaccess_email_list.txt'
    temp_file = '{}.tmp'.format(list_file)
    try:
        # Fetch the current list of all users
        all_users = USER_DB_MANAGER.list_all_users()
        # Filter the user list to ensure valid information for email list data source file
        email_data_source_list = []
        for username, given_name, family_name, email in all_users:
            if not given_name:
                given_name = ''
            if not family_name:
                family_name = ''
            # Simplistic check that the email address is valid
            if isinstance(email, str) and email.find('@') > 0 and email.split('@')[1].find('.') > 0:
                email_data_source_list.append([email, given_name, family_name])
            else:
                try:
                    logger.warning('User account omitted from email list data source file: username: {}, email: {}, given_name: {}, family_name: {}'.format(username, email, given_name, family_name))
                except:
                    pass
        # Sanity check to ensure that the the user list is probably valid
        if len(email_data_source_list) > 10:
            with open(temp_file, 'w') as listfile:
                print('## Data for Sympa member import\n#\n#', file=listfile)
                for email, given_name, family_name in email_data_source_list:
                    print('{} {} {}'.format(email, given_name, family_name), file=listfile)
        else:
            logger.warning('Email list data source file was not updated because the number of valid email addresses is only {}'.format(len(email_data_source_list)))
    except Exception as e:
        status = STATUS_ERROR
        msg = str(e).strip()
        logger.error(msg)
    else:
        if len(email_data_source_list) > 10:
            shutil.copyfile(temp_file, list_file)
            logger.info('Email list file "{}" updated.'.format(list_file))
            os.remove(temp_file)
    return status, msg


# The @webcron decorator executes cron jobs at intervals equal to or greater
# than the cron job's frequency spec. Cron jobs are manually registered in the
# JobHandler database like so
#
#   INSERT INTO `cron` (`name`, `period`, `enabled`) VALUES ('my_cron_job_name', frequency_in_minutes, enabled_0_or_1)
#
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
                    if cronjob['last_run']:
                        last_run_time = cronjob['last_run']
                    else:
                        last_run_time = False
                    logger.debug('cronjob ({} min): {}'.format(cronjob['period'],cronjob['name']))
                    logger.debug('current time: {}'.format(current_time))
                    logger.debug('last run: {}'.format(last_run_time))
                    # Period is an integer in units of minutes
                    time_diff = current_time - last_run_time
                    time_diff_in_minutes = time_diff.total_seconds()/60
                    logger.debug('time diff (min): {}'.format(time_diff_in_minutes))
                    if not last_run_time or time_diff_in_minutes >= cronjob['period']:
                        # Time to run the cron job again
                        logger.info('Running cron job "{}" at "{}".'.format(cronjob['name'], current_time))
                        if cronjob == 'jupyter_prune':
                            webcron_jupyter_prune(current_time)
                        elif cronjob == 'refresh_database_table_cache':
                            webcron_refresh_database_table_cache()
                        elif cronjob == 'prune_job_files':
                            webcron_prune_job_files()
                        elif cronjob == 'sync_email_list':
                            webcron_sync_email_list()
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


# The @allowed_roles decorator must be accompanied by a preceding @authenticated decorator, allowing
# it to restrict access to the decorated function to authenticated users with specified roles.
def allowed_roles(roles_allowed = []):
    # Always allow admin access
    roles_allowed.append('admin')
    # Actual decorator is check_roles
    def check_roles(cls_handler):
        def wrap_execute(handler_execute):
            def wrapper(handler, kwargs):
                response = {
                    "status": STATUS_OK,
                    "msg": ""
                }
                try:
                    roles = handler._token_decoded["roles"]
                    # logger.info('Authenticated user roles: {}'.format(roles))
                    if not any(role in roles for role in roles_allowed):
                        handler.set_status(200)
                        response["status"] = STATUS_ERROR
                        response["message"] = "Access denied."
                        handler.write(response)
                        handler.finish()
                        return
                except:
                    handler.set_status(200)
                    response["status"] = STATUS_ERROR
                    response["message"] = "Error authorizing access."
                    logger.error(response["message"])
                    return
            def _execute(self, transforms, *args, **kwargs):
                wrapper(self, kwargs)
                return handler_execute(self, transforms, *args, **kwargs)
            return _execute
        cls_handler._execute = wrap_execute(cls_handler._execute)
        return cls_handler
    return check_roles


class TileDataHandler(tornado.web.StaticFileHandler):
    def initialize(self, **kwargs):
        self.check_auth()
        super(TileDataHandler, self).initialize(**kwargs)

    def check_auth(self):
        try:
            params = {k: self.get_argument(k) for k in self.request.arguments}
            response = validate_token(params['token'])
            if response['status'] != STATUS_OK:
                self._transforms = []
                self.set_status(401)
                self.finish()
                return
        except:
            self._transforms = []
            self.set_status(401)
            self.finish()
            return


@webcron
class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        # By default the responses are JSON format. Individual GET responses that are text/html must
        # declare the header in the relevant subclass
        self.set_header("Content-Type", "application/json")
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
        self.set_header("Access-Control-Allow-Methods",
                        " POST, PUT, DELETE, OPTIONS, GET")

    def options(self):
        self.set_status(204)
        self.finish()
    
    def get_username_parameter(self):
        response = {
            'status': STATUS_OK,
            'message': ''
        }
        username = None
        try:
            # Authenticated username from auth token:
            authn_username = self._token_decoded["username"].lower()
            # Username provided as request parameter:
            input_username = self.getarg('username', '').lower()
            # If no username parameter is provided, default to the authenticated username
            if input_username == '' or input_username == authn_username:
                username = authn_username
            # If the username parameter is not the authenticated user and the authenticated user is an admin, use the parameter value
            elif 'admin' in self._token_decoded['roles']:
                username = input_username
            # If the username parameter is not the authenticated user and the authenticated user is not an admin, fail
            else:
                username = None
                raise Exception('If username is provided it must match the authenticated user.')
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['message'] = str(e).strip()
            # 400 Bad Request: The server could not understand the request due to invalid syntax.
            # The assumption is that if a function uses `getarg()` to get a required parameter,
            # then the request must be a bad request if this exception occurs.
            self.set_status(400)
            self.write(json.dumps(response))
            self.finish()
            raise e
        return username

    def getarg(self, arg, default=None):
        response = {
            'status': STATUS_OK,
            'message': ''
        }
        value = default
        try:
            # If the request encodes arguments in JSON, parse the body accordingly
            if 'Content-Type' in self.request.headers and self.request.headers['Content-Type'] in ['application/json', 'application/javascript']:
                data = tornado.escape.json_decode(self.request.body)
                if default == None:
                    # The argument is required and thus this will raise an exception if absent
                    value = data[arg]
                else:
                    # Set the value to the default
                    value = default if arg not in data else data[arg]
            # Otherwise assume the arguments are in the default content type
            else:
                # The argument is required and thus this will raise an exception if absent
                if default == None:
                    value = self.get_argument(arg)
                else:
                    value = self.get_argument(arg, default)
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['message'] = str(e).strip()
            logger.error(response['message'])
            # 400 Bad Request: The server could not understand the request due to invalid syntax.
            # The assumption is that if a function uses `getarg()` to get a required parameter,
            # then the request must be a bad request if this exception occurs.
            self.set_status(400)
            self.write(json.dumps(response))
            self.finish()
            raise e
        return value


@authenticated
@allowed_roles(['admin'])
class TriggerWebcronHandler(BaseHandler):
    def post(self):
        response = {
            'status': STATUS_OK,
            'message': ''
        }
        try:
            cronjob = self.getarg('cronjob')
            if cronjob == 'jupyter_prune':
                webcron_jupyter_prune()
            elif cronjob == 'refresh_database_table_cache':
                webcron_refresh_database_table_cache()
            elif cronjob == 'prune_job_files':
                webcron_prune_job_files()
            elif cronjob == 'sync_email_list':
                webcron_sync_email_list()
            else:
                response['msg'] = 'Specified cronjob is not valid.'
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(response)


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
class ProfileHandler(BaseHandler):
    # API endpoint: /profile
    def post(self):
        response = {}
        decoded = self._token_decoded
        exptime =  datetime.datetime.utcfromtimestamp(decoded['exp'])
        ttl = (exptime - datetime.datetime.utcnow()).seconds
        response["status"] = STATUS_OK
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
@allowed_roles(['monitor'])
class UserStatisticsHandler(BaseHandler):
    # API endpoint: /statistics/users
    def get(self):
        response = {}
        try:
            num_users = JOBSDB.get_statistics_session()
            response['status'] = STATUS_OK
            response['message'] = ''
            response['results'] = num_users[0]
        except Exception as e:
            response['message'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(response)

@authenticated
@allowed_roles(['monitor'])
class EndpointStatisticsHandler(BaseHandler):
    # API endpoint: /statistics/endpoints
    def get(self):
        response = {}
        try:
            endpts = JOBSDB.get_statistics_analytics()
            response['status'] = STATUS_OK
            response['message'] = ''
            response['results'] = endpts[0]
        except Exception as e:
            response['message'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(response)

@authenticated
@allowed_roles(['monitor'])
class CutoutStatisticsHandler(BaseHandler):
    # API endpoint: /statistics/cutout
    def get(self):
        response = {}
        try:
            cutout_file_size = JOBSDB.get_statistics_cutout()
            response['status'] = STATUS_OK
            response['message'] = ''
            response['results'] = cutout_file_size[0]
        except Exception as e:
            response['message'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(response)

@authenticated
@allowed_roles(['monitor'])
class QueryStatisticsHandler(BaseHandler):
    # API endpoint: /statistics/query
    def get(self):
        response = {}
        try:
            query_file_size = JOBSDB.get_statistics_query()
            response['status'] = STATUS_OK
            response['message'] = ''
            response['results'] = query_file_size[0]
        except Exception as e:
            response['message'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(json.dumps(response))

@authenticated
@allowed_roles(['monitor'])
class IPStatisticsHandler(BaseHandler):
    # API endpoint: /statistics/ips
    def get(self):
        response = {}
        response['results'] = {}
        for cluster in ['pub','prod']:
            try:
                ip_list = ip.query_pod_logs(cluster = cluster)
                response['status'] = STATUS_OK
                response['message'] = ''
                response['results'][cluster] = ip_list
            except Exception as e:
                response['message'] = str(e).strip()
                response['status'] = STATUS_ERROR
        self.write(response)

@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
@analytics
class ProfileUpdateHandler(BaseHandler):
    # API endpoint: /profile/update/info
    def post(self):
        response = {}
        response["new_token"] = self._token_encoded
        # Enforce lowercase usernames
        try:
            username = self.get_username_parameter()
            first = self.getarg('firstname')
            last = self.getarg('lastname')
            email = self.getarg('email')
        except:
            return
        try:
            status, msg = USER_DB_MANAGER.update_info(username, first, last, email)
            response['status'] = status
            response['message'] = msg
        except Exception as e:
            response['message'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(response)


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
@analytics
class ProfileUpdatePasswordHandler(BaseHandler):
    # API endpoint: /profile/update/password
    def post(self):
        response = {}
        try:
            username = self.get_username_parameter()
            oldpwd = self.getarg('oldpwd')
            newpwd = self.getarg('newpwd')
            database = self.getarg('db', self._token_decoded["db"])
        except:
            return
        try:
            status, message = USER_DB_MANAGER.change_credentials(username, oldpwd, newpwd, database)
            response['status'] = status
            response['message'] = message
        except Exception as e:
            response['message'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(response)


class LoginHandler(BaseHandler):
    # API endpoint: /login
    def post(self):
        response = {
            'status': STATUS_OK,
            'message': ''
        }
        username = self.getarg('username', '')
        email = self.getarg('email', '')
        passwd = self.getarg('password')
        db = self.getarg('database')
        # At least one identifier must be provided
        if username == '' and email == '':
            response["status"] = STATUS_ERROR
            response["message"] = 'Either username or email must be provided.'
            self.set_status(400)
            self.flush()
            self.write(json.dumps(response))
            self.finish()
            return

        # Support login using either username or email
        auth, username, err, update = USER_DB_MANAGER.check_credentials(username, passwd, db, email)
        if not auth:
            if update:
                self.set_status(406)
                response["update"] = True
            else:
                self.set_status(401)
                response["update"] = False
            response["status"] = STATUS_ERROR
            response["message"] = err
            self.flush()
            self.write(json.dumps(response))
            self.finish()
            return
        try:
            name, last, email = USER_DB_MANAGER.get_basic_info(username)
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
            response["status"] = STATUS_ERROR
            response["message"] = 'User not found.'
            self.flush()
            self.write(json.dumps(response))
            self.finish()
            return
        roles = JOBSDB.get_user_roles(username)
        encoded = encode_info(name, last, username, email, db, roles, envvars.JWT_TTL_SECONDS)

        # Return user profile information, user preferences and auth token
        response["message"] = "login"
        response["username"] = username
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
        response = {
            'status': STATUS_OK,
            'message': ''
        }
        response["message"] = "logout {}".format(self._token_decoded["username"])
        response["status"] = JOBSDB.session_logout(self._token_decoded["username"])
        self.write(json.dumps(response))

@analytics
class JobRenewHandler(BaseHandler):
    def get(self, token):
        response = {
            'status': STATUS_OK,
            'message': '',
            'valid': False
        }
        logger.info('Renewal request token: {} ({})'.format(token, self.request.path))
        try:
            status, msg, valid = JOBSDB.renew_job(token)
            response["valid"] = valid
            if status != STATUS_OK:
                response["status"] = STATUS_ERROR
                response["message"] = msg
                self.write(json.dumps(response))
                return
        except Exception as e:
            response["status"] = STATUS_ERROR
            response["message"] = str(e).strip()
            logger.error(response["status"])
        self.write(json.dumps(response))

@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
@analytics
class JobHandler(BaseHandler):
    def put(self):
        '''
        Required parameters:
        - job
        Optional parameters:
        - username
        - user_agent
        - db
        - email
        '''

        def add_request_params_if_supplied(in_array, params):
            dummy_default = '6adc0ba0ae3b46b3919693a02a7190f16adc0ba0ae3b46b3919693a02a7190f18ed22249332e4ffd9dec9b675e865f23'
            for param in params:
                if param not in in_array:
                    val = self.getarg(param, dummy_default)
                    if val != dummy_default:
                        in_array[param] = val
            return in_array
            
        params = {}

        # Applicable to all jobs

        try:
            params["user_agent"] = self.request.headers["User-Agent"]
        except:
            params["user_agent"] = ''
        
        params['username'] = self.get_username_parameter()

        # If the database is not specified in the request, assume the database to
        # use is the one encoded in the authentication token
        params['db'] = self.getarg('db', self._token_decoded["db"])
        if 'db' not in params or not isinstance(params['db'], str) or len(params['db']) < 1:
            params["db"] = self._token_decoded["db"]
        
        # REQUIRED PARAMETER FOR ALL JOBS

        job_type = self.request.path.split('/')[-1]
        if job_type in ['query', 'cutout']:
            params['job'] = job_type
        else:
            params['job'] = self.getarg('job')

        # params['return_list'] = True

        params = add_request_params_if_supplied(params, 
            [ 
                'email',
                'job_name',
                'query',
                'quick',
                'check',
                'compression',
                'filename',
                'positions',
                'release',
                'xsize',
                'ysize',
                'rgb_stiff_colors',
                'rgb_lupton_colors',
                'colors_fits',
                'make_fits',
                'make_rgb_lupton',
                'make_rgb_stiff',
                'rgb_minimum',
                'rgb_stretch',
                'rgb_asinh',
                'discard_fits_files',
                # synchronous option disabled in production
                # 'synchronous',
            ]
        )
        # logger.info(json.dumps(params, indent=2))

        # Enforce job request limits
        if any(role in self._token_decoded["roles"] for role in ['admin', 'unlimited']):
            LIMIT_CUTOUTS_CUTOUTS_PER_JOB = 0
            LIMIT_CUTOUTS_CONCURRENT_JOBS = 0
        else:
            LIMIT_CUTOUTS_CUTOUTS_PER_JOB = envvars.LIMIT_CUTOUTS_CUTOUTS_PER_JOB
            LIMIT_CUTOUTS_CONCURRENT_JOBS = envvars.LIMIT_CUTOUTS_CONCURRENT_JOBS
        params['limits'] = {
            'cutout': {
                'concurrent_jobs': LIMIT_CUTOUTS_CONCURRENT_JOBS,
                'cutouts_per_job': LIMIT_CUTOUTS_CUTOUTS_PER_JOB,
            },
        }

        job_id = ''
        try:
            status, message, job_id = jobutils.submit_job(params)
        except Exception as e:
            status = STATUS_ERROR
            message = str(e).strip()
            logger.error(message)
        out = {
            'status': status,
            'message': message,
            'jobid': job_id,
            'new_token': self._token_encoded
        }
        self.write(json.dumps(out, indent=4))

    # API endpoint: /job/delete
    def delete(self):
        status = STATUS_OK
        message = ''

        username = self.get_username_parameter()

        job_ids = []
        # job-id is a required parameter. Use integer default value so that 
        # the refreshed token will be returned in the case of error
        job_id = self.getarg('job-id', 0)
        if isinstance(job_id, str):
            job_ids.append(job_id)
        elif isinstance(job_id, list):
            job_ids = job_id
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

            if status == STATUS_OK:
                # TODO: Allow specifying job-id "all" to delete all of user's jobs
                conf = {}
                conf["job_type"] = job_type
                conf["namespace"] = jobutils.get_namespace()
                conf["job_name"] = jobutils.get_job_name(job_type, job_id, username)
                conf["job_id"] = job_id
                conf["cm_name"] = jobutils.get_job_configmap_name(job_type, job_id, username)
                try:
                    # Delete the k8s Job if it is still running
                    kubejob.delete_job(conf)
                except:
                    pass
                # Delete the job files on disk
                status, message = JOBSDB.delete_job_files(job_id, username)
                # Mark the job deleted in the JobHandler database
                if status == STATUS_OK:
                    message = JOBSDB.mark_job_deleted(job_id)
                    if message != '':
                        status = STATUS_ERROR
                    else:
                        message = 'Job "{}" deleted.'.format(job_id)
        out = {
            'status': status,
            'message': message,
            'new_token': self._token_encoded
        }
        self.write(json.dumps(out, indent=4))

@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
class JobStatusHandler(BaseHandler):
    # API endpoint: /job/status
    def post(self):
        username = self.get_username_parameter()
        job_id = self.getarg("job-id")
        job_info_list, status, message = JOBSDB.job_status(username, job_id)
        out = {
            'status': status,
            'message': message,
            'jobs': job_info_list,
            'new_token': self._token_encoded
        }
        self.write(json.dumps(out, indent=4, default = json_converter))


# @authenticated
# @allowed_roles(ALLOWED_ROLE_LIST)
# class JobGetHandler(BaseHandler):
#     # API endpoint: /job/[job_id]
#     def get(self, job_id):
#         username = self.get_username_parameter()
#         job_info_list, status, message = JOBSDB.job_status(username, job_id)
#         out = {
#             'status': status,
#             'message': message,
#             'jobs': job_info_list,
#             'new_token': self._token_encoded
#         }
#         self.write(json.dumps(out, indent=4, default = json_converter))


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
class JobListHandler(BaseHandler):
    # API endpoint: /job/list
    def get(self):
        username = self.get_username_parameter()
        job_info_list, status, message = JOBSDB.job_list(username)
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
            # logger.info('/job/start data: {}'.format(json.dumps(data)))
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
            # logger.info('/job/complete data: {}'.format(json.dumps(data)))
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
@allowed_roles(ALLOWED_ROLE_LIST)
@analytics
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
            username = self.get_username_parameter()
            # Get job ID of job to delete
            job_id = self.getarg('job-id')
            job_name = self.getarg('job-name')
            # Determine the type of the job to delete
            job_info_list, request_status, status_msg = JOBSDB.job_status(username, job_id)
            if request_status == STATUS_ERROR:
                status = STATUS_ERROR
                message = status_msg
            else:
                old_job_name = job_info_list[0]['job_name']
        except:
            status = STATUS_ERROR
            message = 'Invalid username or job ID specified.'

        if status == STATUS_OK and old_job_name != job_name:
            message = JOBSDB.rename_job(job_id, job_name)
            if message != '':
                status = STATUS_ERROR
            else:
                message = 'Job "{}" renamed to {}.'.format(job_id, job_name)
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
        csv_text = self.getarg('csvText')
        try:
            valid, msg = validate_cutout_positions_table(csv_text)
            self.write({
                "status": STATUS_OK,
                "valid": valid,
                "msg": msg,
                "csv": csv_text,
                # "type": position_type
            })
        except Exception as e:
            logger.error(str(e).strip())
            self.write({
                "status": STATUS_ERROR,
                "msg": str(e).strip(),
                "csv": csv_text,
            })


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
@analytics
class CheckQuerySyntaxHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            "valid": False
        }
        username = self.get_username_parameter()
        password = JOBSDB.get_password(username)
        db = self._token_decoded["db"]
        query = self.getarg('query')
        try:
            connection = ea.connect(db, user=username, passwd=password)
            cursor = connection.cursor()
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
            cursor.close()
            connection.close()
            self.write(response)
            return
        try:
            cursor.parse(query.encode())
        except Exception as e:
            response['msg'] = str(e).strip()
        else:
            response['valid'] = True
        cursor.close()
        connection.close()
        self.write(response)


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
@analytics
class GetTileLinks(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            "results": [],
            "releases": [],
            'tilename': '',
            'ra_cent': '',
            'dec_cent': '',
            'racmin': '',
            'racmax': '',
            'deccmin': '',
            'deccmax': '',
        }
        username = self.get_username_parameter()
        db = self._token_decoded["db"]
        password = JOBSDB.get_password(username)

        public_releases = ['dr1', 'dr2']
        private_releases = ['sva1', 'y1a1', 'y3a2', 'y6a2']

        public_query_select_custom = {
            'dr1': '''
                '' as fits_image_nobkg_g,
                '' as fits_image_nobkg_r,
                '' as fits_image_nobkg_i,
                '' as fits_image_nobkg_z,
                '' as fits_image_nobkg_y,
                '' as tiff_color_image_nobkg,
            ''',
            'dr2': '''
                fits_image_nobkg_g,
                fits_image_nobkg_r,
                fits_image_nobkg_i,
                fits_image_nobkg_z,
                fits_image_nobkg_y,
                tiff_color_image_nobkg,
            ''',
        }

        public_query_select = {}
        for release in public_releases:
            public_query_select[release] = '''
                {release_custom}
                '{release}' as release,
                g.tilename,
                racmin,
                racmax,
                deccmin,
                deccmax,
                ra_cent,
                dec_cent,
                fits_image_g,
                fits_image_r,
                fits_image_i,
                fits_image_z,
                fits_image_y,
                fits_image_det,
                fits_{release}_main,
                fits_{release}_magnitude,
                fits_{release}_flux,
                tiff_color_image,
                count as nobjects 
            '''.format(release_custom=public_query_select_custom[release],release=release)


        private_query_select_custom = {
            'sva1': '''
                '' as tiff_color_image,
            ''', 
            'y1a1': '''
                '' as tiff_color_image,
            ''',  
            'y3a2': '''
                tiff_color_image,
            ''',  
            'y6a2': '''
                tiff_color_image,
            ''', 
        }

        private_query_select = {}
        for release in private_releases:
            private_query_select[release] = '''
                {release_custom}
                '{release}' as release,
                m.tilename,
                RACMIN,
                RACMAX,
                DECCMIN,
                DECCMAX,
                RA_CENT,
                DEC_CENT,
                fits_image_g,
                fits_catalog_g,
                fits_image_r,
                fits_catalog_r,
                fits_image_i,
                fits_catalog_i,
                fits_image_z,
                fits_catalog_z,
                fits_image_y,
                fits_catalog_y,
                0 as nobjects 
            '''.format(release_custom=private_query_select_custom[release],release=release)

        public_query_from = {
            'dr1': '''
                dr1_tile_info g
            ''',
            'dr2': '''
                dr2_tile_info g
            ''',
        }
        private_query_from = {
            'sva1': '''
                mcarras2.sva1_tile_info m,
                y3a2_coaddtile_geom g 
            ''',
            'y1a1': '''
                mcarras2.y1a1_tile_info m,
                y3a2_coaddtile_geom g 
            ''',
            'y3a2': '''
                mcarras2.y3a2_tile_info m,
                y3a2_coaddtile_geom g 
            ''',
            'y6a2': '''
                mcarras2.y6a2_tile_info m,
                y6a1_coaddtile_geom g 
            ''',
        }

        coords_or_name = self.request.path.split('/')[-1]

        if coords_or_name == 'name':
            # Ignore accidental whitespace around input string
            name = self.getarg('name').strip()

            public_query_where = '''
                g.tilename='{tilename}'
            '''.format(tilename=name)

            private_query_where = '''
                m.tilename=g.tilename AND
                m.tilename='{tilename}'
            '''.format(tilename=name)

        elif coords_or_name == 'coords':
            # Ignore accidental whitespace around input string
            coords = self.getarg('coords').strip()
            coords = re.sub(r'[\(\)]', '', coords)
            coords = coords.split(',')
            ra = float(coords[0].strip())
            dec = float(coords[1].strip())
            if ra > 180:
                ra_adjusted = 360-ra
            else:
                ra_adjusted = ra

            public_query_where = private_query_where = '''
                ({dec} BETWEEN g.UDECMIN AND g.UDECMAX) AND 
                (
                    (
                        g.CROSSRA0='N' AND ({ra} BETWEEN g.URAMIN AND g.URAMAX)
                    )
                    OR 
                    (
                        g.CROSSRA0='Y' AND ({ra_adjusted} BETWEEN g.URAMIN-360 AND g.URAMAX)
                    )
                ) 
            '''.format(ra=ra, dec=dec, ra_adjusted=ra_adjusted)

            # The DESDR tile_info tables include the geometry information but the 
            # DESSCI tables do not
            private_query_where += '''
                AND m.tilename=g.tilename
            '''

        else:
            response['status'] = STATUS_ERROR
            response['msg'] = 'Only coords or name supported. This error should never occur.'
            self.write(response)
            return

        public_query = ''
        for release in public_releases:
            public_query += '''
            SELECT {select_criteria}
            FROM {from_criteria}
            WHERE {where_criteria}
            '''.format(
                select_criteria=public_query_select[release],
                from_criteria=public_query_from[release], 
                where_criteria=public_query_where,
            )
            # Insert UNION ALL between release query blocks
            if release != public_releases[-1]:
                public_query += ' UNION ALL '

        private_query = ''
        for release in private_releases:
            private_query += '''
            SELECT {select_criteria}
            FROM {from_criteria}
            WHERE {where_criteria}
            '''.format(
                select_criteria=private_query_select[release], 
                from_criteria=private_query_from[release], 
                where_criteria=private_query_where,
            )
            # Insert UNION ALL between release query blocks
            if release != private_releases[-1]:
                private_query += ' UNION ALL '

        if envvars.DESACCESS_INTERFACE == 'public':
            query = public_query
        else:
            query = private_query

        try:
            # logger.info(query)
            connection = ea.connect(db, user=username, passwd=password)
            cursor = connection.cursor()
            df = connection.query_to_pandas(query)
            # Limit results to 1000 rows. Should never be necessary.
            df = df[0:1000]
            results = df.to_json(orient='records')
            tile_info = json.loads(results)
            response['results'] = tile_info
            if tile_info:
                response['tilename'] = tile_info[0]['TILENAME']
                response['ra_cent'] = tile_info[0]['RA_CENT']
                response['dec_cent'] = tile_info[0]['DEC_CENT']
                response['racmin'] = tile_info[0]['RACMIN']
                response['racmax'] = tile_info[0]['RACMAX']
                response['deccmin'] = tile_info[0]['DECCMIN']
                response['deccmax'] = tile_info[0]['DECCMAX']
            releases = []
            for release in tile_info:
                # Get the webserver base path for the different releases
                if release['RELEASE'] in ['sva1', 'y1a1']:
                    base_path = 'data/'
                elif release['RELEASE'] in ['dr1', 'dr2']:
                    base_path = 'data/{}/'.format(release['RELEASE'])
                else:
                    base_path = 'data/desarchive/'
                # Set the delimiter to split the URL returned by the database query to 
                # discard the domain information and invalid base path
                if release['RELEASE'] in ['dr1', 'dr2']:
                    delimiter = '{}_tiles/'.format(release['RELEASE'])
                else:
                    delimiter = 'OPS/'
                
                # Iterate through the key-value pairs and generate the download links if the keys exists in the record
                key_fits_main = 'FITS_{}_MAIN'.format(release['RELEASE'])
                key_fits_magnitude = 'FITS_{}_MAGNITUDE'.format(release['RELEASE'])
                key_fits_flux = 'FITS_{}_FLUX'.format(release['RELEASE'])
                key_fits_det = 'FITS_IMAGE_DET'
                key_tiff_image = 'TIFF_COLOR_IMAGE'
                release_keys = [
                    key_fits_main,
                    key_fits_magnitude,
                    key_fits_flux,
                    key_fits_det,
                    key_tiff_image,
                ]
                values = {}
                for key in release_keys:
                    if key not in release or not release[key]:
                        values[key] = ''
                    else:
                        values[key] = 'https://{}{}/{}{}'.format(envvars.BASE_DOMAIN, envvars.BASE_PATH, base_path, release[key].split(delimiter)[1])
                # Iterate through the band-specific key-value pairs and generate the download links if the keys exists in the record
                bands = {}
                for band in ['G', 'R', 'I', 'Z', 'Y']:
                    image_key = 'FITS_IMAGE_{}'.format(band)
                    image_nobkg_key = 'FITS_IMAGE_NOBKG_{}'.format(band)
                    catalog_key = 'FITS_CATALOG_{}'.format(band)
                    band_keys = [
                        image_key,
                        image_nobkg_key,
                        catalog_key,
                    ]
                    band_val = {}
                    for key in band_keys:
                        if key not in release or not release[key]:
                            band_val[key] = ''
                        else:
                            band_val[key] = 'https://{}{}/{}{}'.format(envvars.BASE_DOMAIN, envvars.BASE_PATH, base_path, release[key].split(delimiter)[1])
                    bands[band] = {
                        'image'      : band_val[image_key],
                        'image_nobkg': band_val[image_nobkg_key],
                        'catalog'    : band_val[catalog_key],
                    }
                # Compile the information in an object and append to the returned data structure
                releases.append({
                    'release'    : release['RELEASE'],
                    'bands'      : bands,
                    'num_objects': release['NOBJECTS'],
                    'tiff_image' : values[key_tiff_image],
                    'detection'  : values[key_fits_det],
                    'main'       : values[key_fits_main],
                    'magnitude'  : values[key_fits_magnitude],
                    'flux'       : values[key_fits_flux],
                })
            response['releases'] = releases
            # logger.info(json.dumps(releases, indent=2))
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        cursor.close()
        connection.close()
        self.write(response)


@authenticated
@allowed_roles(['admin'])
class ListUserRolesHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'users': {}
        }
        try:
            # Sync status of help request table records with their Jira issues
            response['msg'] = JOBSDB.sync_help_requests_with_jira()
            # Compile user list with role and help request data
            response['users'] = JOBSDB.get_all_user_roles_and_help_requests()
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        self.write(response)


@authenticated
@allowed_roles(['admin'])
class NotificationsCreateHandler(BaseHandler):
    # Messages are created by admins using the PUT request type
    def put(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        title = self.getarg('title')
        body = self.getarg('body')
        # If the roles array is empty or missing, include the default role
        roles = self.getarg('roles', [])
        if not roles:
            roles = ['default']
        email = self.getarg('email', False)
        try:
            # Insert message into database table
            error_msg = JOBSDB.create_notification(title, body, roles, datetime.datetime.utcnow())
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
            else:
                # Only send email if the roles list includes "default"
                if email and 'default' in roles:
                    logger.info('Sending notification email to email list.')
                    email_utils.email_notify_public_list(EMAIL_LIST_ADDRESS, title, body)
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        self.write(response)


@authenticated
@allowed_roles(['admin'])
class NotificationsDeleteHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        message_id = self.getarg('message-id')
        try:
            # Delete message from database table
            error_msg = JOBSDB.delete_notification(message_id)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        self.write(response)


@authenticated
@allowed_roles(['admin'])
class NotificationsEditHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        id = self.getarg('id')
        title = self.getarg('title')
        body = self.getarg('body')
        roles = self.getarg('roles')
        email = self.getarg('email', False)
        try:
            # Delete message from database table
            error_msg = JOBSDB.edit_notification(id, title, body, roles)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
            else:
                # Only send email if the roles list includes "default"
                if email and 'default' in roles:
                    logger.info('Sending notification email to email list.')
                    email_utils.email_notify_public_list(EMAIL_LIST_ADDRESS, title, body)
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        self.write(response)


@authenticated
@allowed_roles(['admin'])
class JupyterLabPruneHandler(BaseHandler):
    def post(self):
        error_msg = ''
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        try:
            current_time = datetime.datetime.utcnow()
            jupyter_users = JOBSDB.get_role_user_list('jupyter')
            pruned, error_msg = jlab.prune(jupyter_users, current_time)
            logger.info('Pruned Jupyter servers for users: {}'.format(pruned))
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
        except:
            logger.info('Error pruning JupyterLab servers.')
            response['status'] = STATUS_ERROR
            response['msg'] = "Invalid JSON in HTTP request body."
        self.write(response)


@authenticated
@allowed_roles(['jupyter'])
@analytics
class JupyterLabCreateHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'token': '',
            'url': ''
        }
        try:
            username = self.get_username_parameter()
            response['token'] = str(uuid.uuid4()).replace("-", "")
            base_path = '{}/jlab/{}'.format(envvars.FRONTEND_BASE_PATH, username)
            response['url'] = '{}{}?token={}'.format(envvars.FRONTEND_BASE_URL, base_path, response['token'])
            if any(role in self._token_decoded['roles'] for role in ['admin', 'gpu']):
                gpu = self.getarg('gpu', 'false')
            else:
                gpu = 'false'

            error_msg = jlab.create(username, base_path, response['token'], gpu)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(response)


@authenticated
@allowed_roles(['jupyter'])
@analytics
class JupyterLabDeleteHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        try:
            username = self.get_username_parameter()
            error_msg = jlab.delete(username)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(response)


@authenticated
@allowed_roles(['jupyter'])
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
        try:
            username = self.get_username_parameter()
            stat, error_msg = jlab.status(username)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
            response['ready_replicas'] = stat['ready_replicas']
            response['unavailable_replicas'] = stat['unavailable_replicas']
            response['latest_condition_type'] = stat['latest_condition_type']
            response['token'] = stat['token']
            response['creation_timestamp'] = stat['creation_timestamp']
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(json.dumps(response, indent=4, default = json_converter))


@authenticated
@allowed_roles(['jupyter'])
class JupyterLabFileListHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'folders': []
        }
        try:
            username = self.get_username_parameter()
            jupyter_dir = os.path.join('/jobfiles', username, 'jupyter/public')
            jupyter_dirs = []
            if os.path.isdir(jupyter_dir):
                with os.scandir(jupyter_dir) as it:
                    for entry in it:
                        if not entry.name.startswith('.') and entry.is_dir():
                            mod_timestamp = datetime.datetime.fromtimestamp(entry.stat().st_mtime)
                            jupyter_dirs.append({
                                'directory': entry.name,
                                'time': mod_timestamp
                            })
            response['folders'] = jupyter_dirs
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(json.dumps(response, indent=4, default = json_converter))


@authenticated
@allowed_roles(['jupyter'])
@analytics
class JupyterLabFileDeleteHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        token = self.getarg('token')
        try:
            username = self.get_username_parameter()
            jupyter_dir = os.path.join('/jobfiles', username, 'jupyter/public', token)
            if os.path.isdir(jupyter_dir):
                shutil.rmtree(jupyter_dir)
        except Exception as e:
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
            response['status'] = STATUS_ERROR
        self.write(json.dumps(response, indent=4, default = json_converter))


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
class NotificationsFetchHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'messages': []
        }
        # Get roles from token and avoid a database query
        roles = self._token_decoded["roles"]
        username = self._token_decoded["username"]
        message = self.getarg('message')
        try:
            # Validate the API request parameters
            if not isinstance(message, str) or message not in ['all', 'new']:
                response['status'] = STATUS_ERROR
                response['msg'] = 'Parameter "message" must be a message ID or the word "all" or "new".'
            else:
                # Query database for requested messages
                response['messages'], error_msg = JOBSDB.get_notifications(message, username, roles)
                if error_msg != '':
                    response['status'] = STATUS_ERROR
                    response['msg'] = error_msg
        except Exception as e:
            response['msg'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(json.dumps(response, indent=4, default = json_converter))


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
@analytics
class NotificationsMarkHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        username = self.get_username_parameter()
        message_id = self.getarg('message-id')
        try:
            error_msg = JOBSDB.mark_notification_read(message_id, username)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
        except Exception as e:
            response['msg'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(response)


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
@analytics
class UserPreferencesHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'pref': {}
        }
        username = self.get_username_parameter()
        pref = self.getarg('pref')
        try:
            value, error_msg = JOBSDB.get_user_preference(pref, username)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
            else:
                response['pref'] = value
        except Exception as e:
            response['msg'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(response)

    def put(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        username = self.get_username_parameter()
        pref = self.getarg('pref')
        value = self.getarg('value')
        try:
            error_msg = JOBSDB.set_user_preference(pref, value, username)
            if error_msg != '':
                response['status'] = STATUS_ERROR
                response['msg'] = error_msg
        except Exception as e:
            response['msg'] = str(e).strip()
            response['status'] = STATUS_ERROR
        self.write(response)


@analytics
class UserPreferencesStopRenewalEmailsHandler(BaseHandler):
    def get(self):
        self.set_header("Content-Type", "text/html")
        response = '<html></html>'
        renewal_token = self.getarg('token')
        try:
            status, msg, job_table_id, username = JOBSDB.validate_renewal_token(renewal_token)
            if username:
                error_msg = JOBSDB.set_user_preference('sendRenewalEmails', False, username)
                if error_msg != '':
                    response = '<html><body>There was an error disabling job renewal emails: {}</body></html>'.format(error_msg)
                else:
                    response = '<html><body>You will no longer receive job renewal emails.</body></html>'
            else:
                response = '<html><body>There was an error disabling job renewal emails: Link is invalid or has expired.</body></html>'
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
            response = '<html><body>There was an error disabling job renewal emails: {}</body></html>'.format(error_msg)
        self.write(response)


@authenticated
@allowed_roles(['admin'])
class UserDeleteHandler(BaseHandler):
    def delete(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        # Only enable user deletion on public interface
        if envvars.DESACCESS_INTERFACE != 'public':
            response['status'] = STATUS_ERROR
            response['msg'] = "User deletion disabled."
            self.write(response)
            return
        try:
            username = self.getarg('username')
            username = username.lower()
            if username == self._token_decoded["username"]:
                response['status'] = STATUS_ERROR
                response['msg'] = "User may not self-delete."
                self.write(response)
                return
        except Exception as e:
            response['msg'] = str(e).strip()
            response['status'] = STATUS_ERROR
        else:
            try:
                status, msg = USER_DB_MANAGER.delete_user(username)
                if status != STATUS_OK:
                    response['status'] = STATUS_ERROR
                    response['msg'] = msg
            except Exception as e:
                response['status'] = STATUS_ERROR
                response['msg'] = str(e).strip()
                logger.error(response['msg'])
        self.write(response)


@analytics
class UserResetPasswordRequestHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        # Support reset when either username or email is provided
        username = self.getarg('username', '')
        email = self.getarg('email', '')
        try:
            # Generate a reset code
            token, firstname, lastname, email, username, status, msg = USER_DB_MANAGER.create_reset_url(username, email)
            if status != STATUS_OK:
                response['status'] = STATUS_ERROR
                response['msg'] = msg
                self.write(response)
                return
            msg = email_utils.send_reset(username, [email], token)
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
        self.write(response)


class UserResetValidateHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'valid': False
        }
        token = self.getarg('token')
        try:
            valid, username, status, msg = USER_DB_MANAGER.validate_token(token, 24*3600)
            if status != STATUS_OK:
                # There was an error validating the token
                response['status'] = STATUS_ERROR
                response['msg'] = msg
            response['valid'] = valid
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
        self.write(response)


@analytics
class UserResetPasswordHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'reset': False
        }
        token = self.getarg('token')
        password = self.getarg('password')
        try:
            valid, username, status, msg = USER_DB_MANAGER.validate_token(token, 24*3600)
            if status != STATUS_OK:
                # There was an error validating the token
                response['status'] = STATUS_ERROR
                response['msg'] = msg
            elif valid:
                # Update the password
                if not re.fullmatch(PASSWORD_REGEX, password):
                    response['status'] = STATUS_ERROR
                    response['msg'] = PASSWORD_VALIDITY_MESSAGE
                    self.write(response)
                    return
                status, msg = USER_DB_MANAGER.update_password(username, password)
                if status != STATUS_OK:
                    response['status'] = STATUS_ERROR
                    response['msg'] = msg
                    self.write(response)
                    return
                else:
                    response['reset'] = True
                # # Unlock the account
                # status, msg = USER_DB_MANAGER.unlock_account(username)
                # if status != STATUS_OK:
                #     response['status'] = STATUS_ERROR
                #     response['msg'] = msg
                # else:
                #     response['reset'] = True
            else:
                # The token is invalid
                response['msg'] = msg
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
        self.write(response)


@analytics
class UserActivateHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            'activated': False
        }
        # Only enable user activation on public interface
        if envvars.DESACCESS_INTERFACE != 'public':
            response['status'] = STATUS_ERROR
            response['msg'] = "Only for public interface."
            self.write(response)
            return
        token = self.getarg('token')
        try:
            valid, username, status, msg = USER_DB_MANAGER.validate_token(token, 24*3600)
            if status != STATUS_OK:
                response['status'] = STATUS_ERROR
                response['msg'] = msg
            elif valid:
                status, msg = USER_DB_MANAGER.unlock_account(username)
                if status != STATUS_OK:
                    response['status'] = STATUS_ERROR
                    response['msg'] = msg
                else:
                    response['activated'] = True
                    webcron_sync_email_list()
            else:
                response['msg'] = msg
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
            logger.error(response['msg'])
        self.write(response)


@analytics
class UserRegisterHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        # Only enable self-registration on public interface
        if envvars.DESACCESS_INTERFACE != 'public':
            response['status'] = STATUS_ERROR
            response['msg'] = "Self-registration disabled."
            self.write(response)
            return
        username = self.getarg('username')
        username = username.lower()
        password = self.getarg('password')
        firstname = self.getarg('firstname')
        lastname = self.getarg('lastname')
        email = self.getarg('email')
        email = email.lower()
        try:
            # Enforce password length
            if len(password) < 10:
                response['status'] = STATUS_ERROR
                response['msg'] = "Minimum password length is 10 characters."
                self.write(response)
                return
            if len(password) > 30:
                response['status'] = STATUS_ERROR
                response['msg'] = "Maximum password length is 30 characters."
                self.write(response)
                return
            # Limit valid password characters
            if not re.fullmatch(PASSWORD_REGEX, password):
                response['status'] = STATUS_ERROR
                response['msg'] = PASSWORD_VALIDITY_MESSAGE
                self.write(response)
                return
            # Limit other input parameter characters partially to mitigate SQL injection attacks
            if not re.fullmatch(r'[a-z0-9]{3,30}', username):
                response['status'] = STATUS_ERROR
                response['msg'] = 'Valid username characters are: a-z0-9'
                self.write(response)
                return
            if not re.fullmatch(r'[A-Za-z0-9]{1,}', firstname):
                response['status'] = STATUS_ERROR
                response['msg'] = 'Valid given name characters are: A-Za-z0-9'
                self.write(response)
                return
            if not re.fullmatch(r'[A-Za-z0-9]{1,}', lastname):
                response['status'] = STATUS_ERROR
                response['msg'] = 'Valid family name characters are: A-Za-z0-9'
                self.write(response)
                return
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                response['status'] = STATUS_ERROR
                response['msg'] = 'Invalid email address'
                self.write(response)
                return

            # Check to see if username or email are already in use
            status, msg = USER_DB_MANAGER.check_username(username)
            if status != STATUS_OK:
                response['status'] = STATUS_ERROR
                response['msg'] = msg
                self.write(response)
                return
            status, msg = USER_DB_MANAGER.check_email(email)
            if status != STATUS_OK:
                response['status'] = STATUS_ERROR
                response['msg'] = msg
                self.write(response)
                return

            # Create the user by adding them to the user database
            status, msg = USER_DB_MANAGER.create_user(
                username=username, 
                password=password, 
                first=firstname, 
                last=lastname, 
                email=email, 
                lock=True
            )
            if status != STATUS_OK:
                response['status'] = STATUS_ERROR
                response['msg'] = msg
                try:
                    # Clean up the incomplete registration by deleting the user from the user database
                    status, msg = USER_DB_MANAGER.delete_user(username)
                except:
                    logger.error('Unable to delete user {}'.format(username))
                self.write(response)
                return

            # Generate an activation code to enable the new account
            url, firstname, lastname, email, username, status, msg = USER_DB_MANAGER.create_reset_url(username)
            if status != STATUS_OK:
                response['status'] = STATUS_ERROR
                response['msg'] = msg
                try:
                    # Clean up the incomplete registration by deleting the user from the user database
                    status, msg = USER_DB_MANAGER.delete_user(username)
                except:
                    logger.error('Unable to delete user {}'.format(username))
                self.write(response)
                return
            
            # Send the activation email
            try:
                msg = email_utils.send_activation(firstname, lastname, username, email, url)
            except Exception as e:
                response['status'] = STATUS_ERROR
                response['msg'] = str(e).strip()
                self.write(response)
                return
            # Notify DESaccess admins
            try:
                msg = email_utils.email_notify_admins_new_user(firstname, lastname, username, envvars.DESACCESS_ADMIN_EMAILS, url)
            except Exception as e:
                response['status'] = STATUS_ERROR
                response['msg'] = str(e).strip()
                self.write(response)
                return

        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        self.write(response)


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
@analytics
class HelpFormHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        # TODO: Consider reconciling any differences between the
        # user profile data in the auth token with the custom
        # name and email provided by the help form
        username = self.get_username_parameter()
        username = username.lower()
        email = self.getarg('email')
        email = email.lower()
        firstname = self.getarg('firstname')
        lastname = self.getarg('lastname')
        message = self.getarg('message')
        topics = self.getarg('topics')
        othertopic = self.getarg('othertopic')
        # Generate a new Jira ticket using the Jira API
        try:
            # Construct Jira issue body from template file
            jiraIssueTemplateFile = os.path.join(
                os.path.dirname(__file__),
                "jira_issue.tpl"
            )
            with open(jiraIssueTemplateFile) as f:
                templateText = f.read()
            jira_body = Template(templateText).render(
                email=email,
                emaillist=','.join(envvars.DESACCESS_ADMIN_EMAILS),
                firstname=firstname,
                lastname=lastname,
                topics=topics,
                message=message,
                othertopic=othertopic
            )
            # Construct Jira issue body from template file
            emailTemplateFile = os.path.join(
                os.path.dirname(__file__),
                "jira_issue_email.tpl"
            )
            with open(emailTemplateFile) as f:
                templateText = f.read()
            email_body = Template(templateText).render(
                email=email,
                firstname=firstname,
                lastname=lastname,
                topics=topics,
                message=message,
                othertopic=othertopic
            )
            if envvars.DESACCESS_INTERFACE == 'public':
                issuetype = 'DESaccess public help request ({})'.format(username)
            else:
                issuetype = 'DESaccess private help request ({})'.format(username)
            issue = {
                'project' : {'key': 'DESRELEASE'},
                'issuetype': {'name': 'Task'},
                'summary': issuetype,
                'description' : jira_body,
                #'reporter' : {'name': 'desdm-wufoo'},
            }
            new_jira_issue = JIRA_API.create_issue(fields=issue)
            assignment_success = False
            try:
                assignment_success = JIRA_API.assign_issue(new_jira_issue, envvars.JIRA_DEFAULT_ASSIGNEE)
            except:
                pass
            if not assignment_success:
                logger.error('Unable to assign to Jira user: {}'.format(envvars.JIRA_DEFAULT_ASSIGNEE))
            data = {
                'username': username,
                'firstname': firstname,
                'lastname': lastname,
                'email': email,
                'message': message,
                'topics': topics,
                'othertopic': othertopic,
                'jira_issue_number': '{}'.format(new_jira_issue),
            }
            response['msg'] = 'Jira issue created: {}'.format(data['jira_issue_number'])
            try:
                # Send notification email to user and to admins via list
                # recipients, error_msg = JOBSDB.get_admin_emails()
                error_msg = ''
                recipients = envvars.DESACCESS_ADMIN_EMAILS + [email]
                if error_msg == '':
                    email_utils.help_request_notification(username, recipients, data['jira_issue_number'], email_body)
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
@allowed_roles(['admin'])
class UpdateUserRolesHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        username = self.getarg('username')
        new_roles = self.getarg('new_roles')
        try:
            response['msg'] = JOBSDB.update_user_roles(username, new_roles)
            if response['msg'] != '':
                response['status'] = STATUS_ERROR
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        self.write(response)


@authenticated
@allowed_roles(['admin'])
class SetUserRolesHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        username = self.getarg('username')
        roles = self.getarg('roles')
        try:
            response['msg'] = JOBSDB.set_user_roles(username, roles)
            if response['msg'] != '':
                response['status'] = STATUS_ERROR
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        self.write(response)


@authenticated
@allowed_roles(['admin'])
class ResetUserRoleHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": ""
        }
        username = self.getarg('username')
        try:
            response['msg'] = JOBSDB.reset_user_roles(username)
            if response['msg'] != '':
                response['status'] = STATUS_ERROR
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        self.write(response)


@authenticated
@allowed_roles(['admin'])
class ListUsersHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            "users": {}
        }
        username = self.getarg('username')
        try:
            if username == 'all':
                response['users'] = USER_DB_MANAGER.list_all_users()
            else:
                response['users'] = USER_DB_MANAGER.get_basic_info(username)
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        self.write(response)


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
class TablesListAllHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            "tables": {}
        }
        username = self.get_username_parameter()
        db = self._token_decoded["db"]
        password = JOBSDB.get_password(username)
        query = """
        SELECT t.table_name, a.num_rows AS NROWS
        FROM DES_ADMIN.CACHE_TABLES t, all_tables a
        WHERE a.owner || '.' || a.table_name = t.table_name
        UNION
        SELECT t.table_name, a.num_rows AS NROWS
        FROM DES_ADMIN.CACHE_TABLES t, all_tables a
        WHERE a.table_name = t.table_name AND a.owner = 'DES_ADMIN'
        ORDER BY table_name;
        """
        try:
            connection = ea.connect(db, user=username, passwd=password)
            cursor = connection.cursor()
            df = connection.query_to_pandas(query)
            response['tables'] = json.loads(df.to_json(orient='records'))
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        cursor.close()
        connection.close()
        self.write(response)


@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
class TablesDescribeTableHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            "schema": {}
        }
        username = self.get_username_parameter()
        db = self._token_decoded["db"]
        password = JOBSDB.get_password(username)
        # Get table name
        table = self.getarg('table').upper()
        # If there is a period in the table name, set owner name from this
        # and ignore any owner parameter in the request
        if '.' in table:
            owner = table.split('.')[0]
            table = table.split('.')[1]
        else:
            owner = self.getarg('owner', '').upper()
            if owner == '':
                owner = username.upper()
            elif owner == "NOBODY":
                owner = "DES_ADMIN"

        # Sanitize inputs
        if not re.fullmatch(r'[A-Z0-9_]+', table) or not re.fullmatch(r'[A-Z0-9_]+', owner):
            response['status'] = STATUS_ERROR
            response['msg'] = 'Invalid table or owner name.'
            self.write(response)
            return

        query = """
        select atc.column_name, atc.data_type,
        case atc.data_type
        when 'NUMBER' then '(' || atc.data_precision || ',' || atc.data_scale || ')'
        when 'VARCHAR2' then atc.CHAR_LENGTH || ' characters'
        else atc.data_length || ''  end as DATA_FORMAT,
        acc.comments
        from all_tab_cols atc , all_col_comments acc
        where atc.owner = '{owner}' and atc.table_name = '{table}'
        and acc.owner = '{owner}' and acc.table_name = '{table}'
        and acc.column_name = atc.column_name
        order by atc.column_name
        """.format(owner=owner, table=table)
        try:
            connection = ea.connect(db, user=username, passwd=password)
            cursor = connection.cursor()
            df = connection.query_to_pandas(query)
            response['schema'] = json.loads(df.to_json(orient='records'))
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        cursor.close()
        connection.close()
        self.write(response)

@authenticated
@allowed_roles(ALLOWED_ROLE_LIST)
class TablesListMineHandler(BaseHandler):
    def post(self):
        response = {
            "status": STATUS_OK,
            "msg": "",
            "tables": {}
        }
        username = self.get_username_parameter()
        db = self._token_decoded["db"]
        password = JOBSDB.get_password(username)
        query = """
        SELECT t.table_name, s.bytes/1024/1024/1024 SIZE_GBYTES, t.num_rows NROWS
        FROM user_segments s, user_tables t
        WHERE s.segment_name = t.table_name ORDER BY t.table_name
        """
        try:
            connection = ea.connect(db, user=username, passwd=password)
            cursor = connection.cursor()
            df = connection.query_to_pandas(query)
            # Limit results to 1000 rows. Should never be necessary.
            df = df[0:1000]
            response['tables'] = json.loads(df.to_json(orient='records'))
        except Exception as e:
            response['status'] = STATUS_ERROR
            response['msg'] = str(e).strip()
        cursor.close()
        connection.close()
        self.write(response)


def make_app(basePath=''):
    settings = {"debug": True}
    return tornado.web.Application(
        [
            (r"{}/job/status?".format(basePath), JobStatusHandler),
            # (r"{}/job/(.*)?".format(basePath), JobGetHandler),
            (r"{}/job/list?".format(basePath), JobListHandler),
            (r"{}/job/delete?".format(basePath), JobHandler),
            (r"{}/job/submit?".format(basePath), JobHandler),
            (r"{}/job/cutout?".format(basePath), JobHandler),
            (r"{}/job/query?".format(basePath), JobHandler),
            (r"{}/job/complete?".format(basePath), JobComplete),
            (r"{}/job/start?".format(basePath), JobStart),
            (r"{}/job/rename?".format(basePath), JobRename),
            (r"{}/job/renew/(.*)?".format(basePath), JobRenewHandler),
            (r"{}/login/?".format(basePath), LoginHandler),
            (r"{}/logout/?".format(basePath), LogoutHandler),
            (r"{}/profile/?".format(basePath), ProfileHandler),
            (r"{}/profile/update/info?".format(basePath), ProfileUpdateHandler),
            (r"{}/profile/update/password?".format(basePath), ProfileUpdatePasswordHandler),
            (r"{}/user/role/update?".format(basePath), UpdateUserRolesHandler),
            (r"{}/user/role/add?".format(basePath), SetUserRolesHandler),
            (r"{}/user/role/reset?".format(basePath), ResetUserRoleHandler),
            (r"{}/user/role/list?".format(basePath), ListUserRolesHandler),
            (r"{}/user/list?".format(basePath), ListUsersHandler),
            (r"{}/user/preference?".format(basePath), UserPreferencesHandler),
            (r"{}/user/preference/stoprenewalemails?".format(basePath), UserPreferencesStopRenewalEmailsHandler),
            (r"{}/user/register?".format(basePath), UserRegisterHandler),
            (r"{}/user/activate?".format(basePath), UserActivateHandler),
            (r"{}/user/delete?".format(basePath), UserDeleteHandler),
            (r"{}/user/reset/request?".format(basePath), UserResetPasswordRequestHandler),
            (r"{}/user/reset/password?".format(basePath), UserResetPasswordHandler),
            (r"{}/user/reset/validate?".format(basePath), UserResetValidateHandler),
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
            (r"{}/page/cutout/csv/validate/?".format(basePath), ValidateCsvHandler),
            (r"{}/page/db-access/check/?".format(basePath), CheckQuerySyntaxHandler),
            (r"{}/page/help/form/?".format(basePath), HelpFormHandler),
            (r"{}/data/coadd/(.*)?".format(basePath),      TileDataHandler, {'path': '/des004/coadd'}),
            (r"{}/data/desarchive/(.*)?".format(basePath), TileDataHandler, {'path': '/des003/desarchive'}),
            (r"{}/data/dr1/(.*)?".format(basePath), TileDataHandler, {'path': '/tiles/dr1'}),
            (r"{}/data/dr2/(.*)?".format(basePath), TileDataHandler, {'path': '/tiles/dr2'}),
            (r"{}/dev/debug/trigger?".format(basePath), DebugTrigger),
            (r"{}/dev/db/wipe?".format(basePath), DbWipe),
            (r"{}/dev/webcron?".format(basePath), TriggerWebcronHandler),
            (r"{}/tiles/info/coords?".format(basePath), GetTileLinks),
            (r"{}/tiles/info/name?".format(basePath), GetTileLinks),
            (r"{}/tables/list/all?".format(basePath), TablesListAllHandler),
            (r"{}/tables/list/mine?".format(basePath), TablesListMineHandler),
            (r"{}/tables/describe?".format(basePath), TablesDescribeTableHandler),
            (r"{}/statistics/users?".format(basePath), UserStatisticsHandler),
            (r"{}/statistics/endpoints?".format(basePath), EndpointStatisticsHandler),
            (r"{}/statistics/ips?".format(basePath), IPStatisticsHandler),
            (r"{}/statistics/query?".format(basePath), QueryStatisticsHandler),
            (r"{}/statistics/cutout?".format(basePath), CutoutStatisticsHandler),
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
