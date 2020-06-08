import os
import uuid
from jinja2 import Template
import secrets
import kubejob
import yaml
import envvars
import mysql.connector
import json
import datetime
import logging
from cryptography.fernet import Fernet
import base64
import re
import email_utils

STATUS_OK = 'ok'
STATUS_ERROR = 'error'

log_format = "%(asctime)s  %(name)8s  %(levelname)5s  %(message)s"
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.FileHandler("test.log"), logging.StreamHandler()],
    format=log_format,
)
logger = logging.getLogger("main")


def password_encrypt(password):
    secret = envvars.JWT_HS256_SECRET
    key = base64.urlsafe_b64encode(secret.encode('UTF-8'))
    locksmith = Fernet(key)
    return locksmith.encrypt(password.encode('UTF-8')).decode('UTF-8')


def password_decrypt(password):
    secret = envvars.JWT_HS256_SECRET
    key = base64.urlsafe_b64encode(secret.encode('UTF-8'))
    locksmith = Fernet(key)
    return locksmith.decrypt(password.encode('UTF-8')).decode('UTF-8')


class JobsDb:
    def __init__(self, mysql_host, mysql_user, mysql_password, mysql_database):
        self.host = mysql_host
        self.user = mysql_user
        self.password = mysql_password
        self.database = mysql_database
        self.cur = None
        self.cnx = None
        self.db_schema_version = 7
        self.table_names = [
            'job',
            'query',
            'cutout',
            'role',
            'session',
            'meta'
        ]

    def open_db_connection(self):
        if self.cnx is None or self.cur is None:
            # Open database connection
            self.cnx = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database,
            )
            # Get database cursor object
            self.cur = self.cnx.cursor()

    def close_db_connection(self):
        if self.cnx != None and self.cur != None:
            try:
                # Commit changes to database and close connection
                self.cnx.commit()
                self.cur.close()
                self.cnx.close()
                self.cur = None
                self.cnx = None
            except Exception as e:
                error = str(e).strip()
                self.cur = None
                self.cnx = None
                return False, error

    def parse_sql_commands(self, sql_file):
        msg = ''
        status = STATUS_OK
        commands = []
        try:
            with open(sql_file) as f:
                dbUpdateSql = f.read()
            #Individual SQL commands must be separated by the custom delimiter '#---'
            for sqlCommand in dbUpdateSql.split('#---'):
                if len(sqlCommand) > 0 and not sqlCommand.isspace():
                    commands.append(sqlCommand)
        except Exception as e:
            msg = str(e).strip()
            logger.error(msg)
            status = STATUS_ERROR
        return [commands, status, msg]


    def update_db_tables(self):
        self.open_db_connection()
        try:
            current_schema_version = 0
            try:
                # Get currently applied database schema version if tables have already been created
                self.cur.execute(
                    "SELECT `schema_version` FROM `meta` LIMIT 1"
                )
                for (schema_version,) in self.cur:
                    current_schema_version = schema_version
                logger.info("schema_version taken from meta table")
            except:
                logger.info("meta table not found")
            logger.info('current schema version: {}'.format(current_schema_version))
            # Update the database schema if the versions do not match
            if current_schema_version < self.db_schema_version:
                # Sequentially apply each DB update until the schema is fully updated
                for db_update_idx in range(current_schema_version+1, self.db_schema_version+1, 1):
                    sql_file = os.path.join(os.path.dirname(__file__), "db_schema_update", "db_schema_update.{}.sql".format(db_update_idx))
                    commands, status, msg = self.parse_sql_commands(sql_file)
                    for cmd in commands:
                        logger.info('Applying SQL command from "{}":'.format(sql_file))
                        logger.info(cmd)
                        # Apply incremental update
                        self.cur.execute(cmd)
                    # Update `meta` table to match
                    logger.info("Updating `meta` table...")
                    try:
                        self.cur.execute(
                            "INSERT INTO `meta` (`schema_version`) VALUES ({})".format(db_update_idx)
                        )
                    except:
                        self.cur.execute(
                            "UPDATE `meta` SET `schema_version`={}".format(db_update_idx)
                        )
                    self.cur.execute(
                        "SELECT `schema_version` FROM `meta` LIMIT 1"
                    )
                    for (schema_version,) in self.cur:
                        logger.info('Current schema version: {}'.format(schema_version))
        except Exception as e:
            logger.error(str(e).strip())

        self.close_db_connection()

    def init_db(self):
        try:
            # Initialize the database tables with info such as admin accounts
            # with open(os.path.join(os.path.dirname(__file__), "db_init", "db_init.yaml")) as f:
            self.open_db_connection()
            with open(os.path.join(envvars.CONFIG_FOLDER_ROOT, "config", "db_init.yaml")) as f:
                db_init = yaml.safe_load(f.read())
            roles_added = []
            for role in db_init['role']:
                # Ignore redundant role definitions
                if role not in roles_added:
                    roles_added.append(role)
                    self.cur.execute(
                        (
                            "INSERT INTO `role` "
                            "(username, role_name) "
                            "VALUES (%s, %s)"
                        ),
                        (
                            role["username"],
                            role["role_name"],
                        )
                    )
            self.close_db_connection()
        except Exception as e:
            logger.error(str(e).strip())

    def reinitialize_tables(self):
        try:
            # Drop all existing database tables
            self.open_db_connection()
            for table in self.table_names:
                self.cur.execute("DROP TABLE IF EXISTS `{}`".format(table))
            self.close_db_connection()

            # Sequentially apply updates to database schema until latest version is reached
            self.update_db_tables()

            # Initialize database
            self.init_db()

        except Exception as e:
            logger.error(str(e).strip())


    def validate_apitoken(self, apitoken):
        self.open_db_connection()
        self.cur.execute(
            "SELECT id,user,uuid FROM `job` WHERE apitoken = '{}' LIMIT 1".format(
                apitoken)
        )
        # If there is a result, assume only one exists and return the record id, otherwise return None
        rowId = None
        for (id,user,uuid) in self.cur:
            rowId = id
        self.close_db_connection()
        return rowId

    def job_status(self, username, job_id):
        self.open_db_connection()
        request_status = 'ok'
        msg = ''
        job_info_list = []
        try:
            if job_id == "all":
                self.cur.execute(
                    (
                    "SELECT type, name, uuid, status, time_start, time_complete "
                    "FROM `job` WHERE user = %s AND `deleted` = 0 ORDER BY time_start DESC"
                    ),
                    (
                    username,
                    )
                )
                job_info = None
                for (type, name, uuid, status, time_start, time_complete) in self.cur:
                    job_info = {}
                    job_info["job_type"] = type
                    job_info["job_name"] = name
                    job_info["job_id"] = uuid
                    job_info["job_status"] = status
                    job_info["job_time_start"] = time_start
                    job_info["job_time_complete"] = time_complete
                    job_info_list.append(job_info)
            else:
                self.cur.execute(
                    (
                    "SELECT type, name, uuid, status, time_start, time_complete "
                    "FROM `job` "
                    "WHERE user = %s AND uuid = %s LIMIT 1"
                    ),
                    (
                        username,
                        job_id
                    )
                )
                job_info = None
                for (type, name, uuid, status, time_start, time_complete) in self.cur:
                    job_info = {}
                    job_info["job_type"] = type
                    job_info["job_name"] = name
                    job_info["job_id"] = uuid
                    job_info["job_status"] = status
                    job_info["job_time_start"] = time_start
                    job_info["job_time_complete"] = time_complete
                    job_info_list.append(job_info)
                if job_info == None:
                    request_status = 'error'
                    msg = 'Error retrieving job status for user {}, job_id {}'.format(username, job_id)
        except:
            request_status = 'error'
            msg = 'Error retrieving job status for user {}, job_id {}'.format(username, job_id)
        self.close_db_connection()
        return [job_info_list, request_status, msg]

    def register_job(self, conf):
        self.open_db_connection()
        if 'email' in conf:
            email = conf['email']
        else:
            email = ''
        newJobSql = (
            "INSERT INTO `job` "
            "(user, type, name, uuid, status, apitoken, user_agent, email, msg) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        )
        newJobInfo = (
            conf["configjob"]["metadata"]["username"],
            conf["configjob"]["kind"],
            conf["configjob"]["metadata"]["job_name"],
            conf["configjob"]["metadata"]["jobId"],
            'init',
            conf["configjob"]["metadata"]["apiToken"],
            conf["user_agent"],
            email,
            ''
        )
        self.cur.execute(newJobSql, newJobInfo)
        if self.cur.lastrowid:
            if conf["configjob"]["kind"] == 'query':
                newQuerySql = (
                    "INSERT INTO `query` "
                    "(job_id, query, files, sizes, data) "
                    "VALUES (%s, %s, %s, %s, %s)"
                )
                newQueryInfo = (
                    self.cur.lastrowid,
                    conf["configjob"]["spec"]["inputs"]["queryString"],
                    '[]',
                    '[]',
                    '{}',
                )
                self.cur.execute(newQuerySql, newQueryInfo)
            elif conf["configjob"]["kind"] == 'test':
                # TODO: Add test table row associated with test task
                logger.info('Created new job of type "test"')
            elif conf["configjob"]["kind"] == 'cutout':
                opt_vals = {}
                for key in ['ra', 'dec', 'coadd', 'xsize', 'ysize', 'rgb_minimum', 'rgb_stretch', 'rgb_asinh']:
                    if key in conf["configjob"]["spec"]:
                        opt_vals[key] = conf["configjob"]["spec"][key]
                    else:
                        opt_vals[key] = None
                self.cur.execute(
                    (
                        "INSERT INTO `cutout` "
                        "(`job_id`, `db`, `release`, `ra`, `dec`, `coadd`, `make_tiffs`, "
                        "make_fits, make_pngs, make_rgb_lupton, make_rgb_stiff, "
                        "return_list, xsize, ysize, colors_rgb, colors_fits, "
                        "rgb_minimum, rgb_stretch, rgb_asinh) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    ),
                    (
                        self.cur.lastrowid,
                        conf["configjob"]["spec"]["db"],
                        conf["configjob"]["spec"]["release"],
                        opt_vals['ra'],
                        opt_vals['dec'],
                        opt_vals['coadd'],
                        conf["configjob"]["spec"]["make_tiffs"],
                        conf["configjob"]["spec"]["make_fits"],
                        conf["configjob"]["spec"]["make_pngs"],
                        conf["configjob"]["spec"]["make_rgb_lupton"],
                        conf["configjob"]["spec"]["make_rgb_stiff"],
                        conf["configjob"]["spec"]["return_list"],
                        conf["configjob"]["spec"]["xsize"],
                        conf["configjob"]["spec"]["ysize"],
                        conf["configjob"]["spec"]["colors_rgb"],
                        conf["configjob"]["spec"]["colors_fits"],
                        opt_vals['rgb_minimum'],
                        opt_vals['rgb_stretch'],
                        opt_vals['rgb_asinh'],
                    )
                )
        else:
            logger.error("Error inserting new job.")
        self.close_db_connection()

    def update_job_start(self, apitoken):
        error_msg = None
        rowId = self.validate_apitoken(apitoken)
        if not isinstance(rowId, int):
            error_msg = 'Invalid apitoken'
            return error_msg
        self.open_db_connection()
        try:
            updateJobSql = (
                "UPDATE `job` "
                "SET status=%s, time_start=%s "
                "WHERE id=%s"
            )
            updateJobInfo = (
                'started',
                datetime.datetime.utcnow(),
                rowId
            )
            self.cur.execute(updateJobSql, updateJobInfo)
        except Exception as e:
            error_msg = str(e).strip()
            self.close_db_connection()
            return error_msg
        if self.cur.rowcount != 1:
            error_msg = 'Error updating job record'
        self.close_db_connection()
        return error_msg

    def update_job_complete(self, apitoken, response):
        error_msg = None
        rowId = self.validate_apitoken(apitoken)
        if not isinstance(rowId, int):
            error_msg = 'Invalid apitoken'
            return error_msg
        self.open_db_connection()
        try:
            response_status = response["status"]
            if response_status == "ok":
                job_status = "success"
            elif response_status == "error":
                job_status = "failure"
            else:
                job_status = "unknown"
        except:
            job_status = "unknown"
        try:
            updateJobSql = (
                "UPDATE `job` "
                "SET status=%s, time_complete=%s, msg=%s "
                "WHERE id=%s"
            )
            updateJobInfo = (
                job_status,
                datetime.datetime.utcnow(),
                '' if response['msg'] is None else response['msg'],
                rowId
            )
            self.cur.execute(updateJobSql, updateJobInfo)
        except Exception as e:
            error_msg = str(e).strip()
            self.close_db_connection()
            return error_msg
        if self.cur.rowcount != 1:
            error_msg = 'Error updating job record {}'.format(rowId)
        else:
            selectJobSql = (
                "SELECT user,type,uuid,name,email from `job` WHERE id=%s"
            )
            selectJobInfo = (
                rowId,
            )
            self.cur.execute(selectJobSql, selectJobInfo)
            for (user, type, uuid, name, email) in self.cur:
                job_id = uuid
                if job_status == "unknown":
                    logger.warning('Job {} completion report did not include a final status.'.format(job_id))
                conf = {"job": type}
                conf['namespace'] = get_namespace()
                conf["job_name"] = get_job_name(type, job_id, user)
                conf["job_id"] = job_id
                conf["cm_name"] = get_job_configmap_name(type, job_id, user)
                kubejob.delete_job(conf)
                if type == 'test':
                    updateQuerySql = (
                        "UPDATE `job` "
                        "SET msg=%s "
                        "WHERE id=%s"
                    )
                    updateQueryInfo = (
                        '' if response['msg'] is None else response['msg'],
                        rowId
                    )
                    self.cur.execute(updateQuerySql, updateQueryInfo)
                elif type == 'query':
                    updateQuerySql = (
                        "UPDATE `query` "
                        "SET files=%s, sizes=%s, data=%s "
                        "WHERE job_id=%s"
                    )
                    updateQueryInfo = (
                        json.dumps(response["files"]),
                        json.dumps(response["sizes"]),
                        json.dumps(response["data"]),
                        rowId
                    )
                    self.cur.execute(updateQuerySql, updateQueryInfo)
                elif type == 'cutout':
                    self.cur.execute(
                        (
                            "UPDATE `cutout` "
                            "SET file_list=%s, file_size=%s, file_number=%s "
                            "WHERE job_id=%s"
                        ),
                        (
                            json.dumps(response["files"]),
                            str(response["sizes"]),
                            len(response["files"]),
                            rowId
                        )
                    )
                if len(email) > 4:
                    # if len(name) > 0:
                    #     job_ref = name
                    # else:
                    #     job_ref = job_id
                    email_utils.send_note(user, job_id, email)
        self.close_db_connection()
        return error_msg

    def session_login(self, username, token, ciphertext):
        self.open_db_connection()
        status = "ok"
        try:
            self.cur.execute(
                (
                    "SELECT id from `session` WHERE username=%s"
                ),
                (
                    username,
                )
            )
            session_id = None
            for (id,) in self.cur:
                session_id = id
            if isinstance(session_id, int):
                self.cur.execute(
                    (
                        "UPDATE `session` "
                        "SET last_login=%s, password=%s "
                        "WHERE username=%s"
                    ),
                    (
                        datetime.datetime.utcnow(),
                        ciphertext,
                        username,
                    )
                )
            else:
                self.cur.execute(
                    (
                        "INSERT INTO `session` "
                        "(username, last_login, password) "
                        "VALUES (%s, %s, %s) "
                    ),
                    (
                        username,
                        datetime.datetime.utcnow(),
                        ciphertext,
                    )
                )
        except Exception as e:
            logger.error(str(e).strip())
            status = "error"
        self.close_db_connection()
        return status

    def session_logout(self, username):
        # This function assumes the logout action is already authorized
        self.open_db_connection()
        status = "ok"
        try:
            self.cur.execute(
                (
                    "UPDATE `session` "
                    "SET password=%s "
                    "WHERE username=%s"
                ),
                (
                    '',
                    username,
                )
            )
            if self.cur.rowcount < 1:
                status = "warning"
                logger.warning('No record in session table found for user {}'.format(username))
        except Exception as e:
            logger.error(str(e).strip())
            status = "error"
        self.close_db_connection()
        return status

    def get_user_roles(self, username):
        self.open_db_connection()
        roles = []
        try:
            self.cur.execute(
                (
                    "SELECT role_name from `role` WHERE username=%s"
                ),
                (
                    username,
                )
            )
            for (role_name,) in self.cur:
                if isinstance(role_name, str):
                    roles.append(role_name)
        except Exception as e:
            logger.error(str(e).strip())
        self.close_db_connection()
        return roles

    def get_password(self, username):
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "SELECT password from `session` WHERE username=%s"
                ),
                (
                    username,
                )
            )
            ciphertext = None
            for (password,) in self.cur:
                ciphertext = password
            if isinstance(ciphertext, str):
                return password_decrypt(ciphertext)
        except Exception as e:
            logger.error(str(e).strip())
        self.close_db_connection()

    def delete_job(self, job_id):
        error_msg = ''
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "UPDATE `job` SET `deleted`=%s WHERE `uuid` = %s"
                ),
                (
                    True,
                    job_id,
                )
            )
            if self.cur.rowcount != 1:
                error_msg = 'Error updating job record'
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

# Get global instance of the job handler database interface
JOBSDB = JobsDb(
    mysql_host=envvars.MYSQL_HOST,
    mysql_user=envvars.MYSQL_USER,
    mysql_password=envvars.MYSQL_PASSWORD,
    mysql_database=envvars.MYSQL_DATABASE
)

def get_namespace():
    # When running in a pod, the namespace should be determined automatically,
    # otherwise we assume the local development is in the default namespace
    try:
        with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as file:
            namespace = file.read().replace('\n', '')
    except:
        try:
            namespace = os.environ['NAMESPACE']
        except:
            namespace = 'default'
    return namespace

def generate_job_id():
    return str(uuid.uuid4()).replace("-", "")


def get_job_name(jobType, jobId, username):
    return "{}-{}-{}".format(jobType, jobId, username)


def get_job_configmap_name(jobType, jobId, username):
    return "{}-{}-{}-cm".format(jobType, jobId, username)


def get_job_template_base():
    # Import base task config template file
    jobConfigTemplateFile = os.path.join(
        os.path.dirname(__file__),
        "jobconfig_base.tpl.yaml"
    )
    with open(jobConfigTemplateFile) as f:
        templateText = f.read()
    return Template(templateText)


def get_job_template(job_type):
    # Import task config template file
    jobConfigTemplateFile = os.path.join(
        os.path.dirname(__file__),
        "des-tasks",
        job_type,
        'worker',
        "jobconfig_spec.tpl.yaml"
    )
    with open(jobConfigTemplateFile) as f:
        templateText = f.read()
    return Template(templateText)


def submit_job(params):

    def filter_and_order_colors(colorString):
        # Returns a comma-separated string of color characters ordered by wavelength
        if isinstance(colorString, str):
            # Discard all invalid characters and delete redundancies
            color_list_filtered_deduplicated = list(set(re.sub(r'([^grizy])', '', colorString.lower())))
            ordered_colors = []
            # Order the colors from long to short wavelength
            for color in list('yzirg'):
                if color in color_list_filtered_deduplicated:
                    ordered_colors.append(color)
            return ','.join(ordered_colors)

    status = STATUS_OK
    msg = ''
    try:
        # Common configurations to all tasks types:
        username = params["username"].lower()
        password = JOBSDB.get_password(username)
        job_type = params["job"]
        job_id = generate_job_id()
        conf = {}
        conf["job"] = job_type
        conf["namespace"] = get_namespace()
        conf["cm_name"] = get_job_configmap_name(conf["job"], job_id, username)
        conf["host_network"] = envvars.HOST_NETWORK
        conf["user_agent"] = params["user_agent"]
        if 'job_name' in params and isinstance(params['job_name'], str):
            if len(params['job_name']) > 128 or len(params['job_name']) == 0:
                status = STATUS_ERROR
                msg = 'job_name valid length is 1-128 characters'
                return status,msg,''
            elif not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$', params['job_name']):
                status = STATUS_ERROR
                msg = "Custom job name must consist of lower case alphanumeric characters, '-' and/or '.', and must start and end with an alphanumeric character."
                return status,msg,''
            else:
                conf['job_name'] = params['job_name'].encode('utf-8').decode('unicode-escape')
        else:
            conf["job_name"] = get_job_name(conf["job"], job_id, username)
        if 'email' in params and isinstance(params['email'], str):
            # This is only a rudimentary validation of an email address
            if re.match(r"[^@]+@[^@]+\.[^@]+", params['email']):
                conf["email"] = params['email']
            else:
                status = STATUS_ERROR
                msg = 'Invalid email address'
                return status,msg,''
    except:
        status = STATUS_ERROR
        msg = 'username, job, and user_agent must be specified.'
        return status,msg,''
    template = get_job_template(job_type)
    base_template = get_job_template_base()
    # Render the base YAML template for the job configuration data structure
    conf["configjob"] = yaml.safe_load(base_template.render(
        taskType=conf["job"],
        jobName=job_id,
        job_name=conf['job_name'],
        jobId=job_id,
        username=username,
        password=password,
        logFilePath="./output/{}/{}.log".format(conf["job"], job_id),
        apiToken=secrets.token_hex(16),
        apiBaseUrl=envvars.API_BASE_URL,
        persistentVolumeClaim=envvars.PVC_NAME_BASE,
        debug=envvars.DEBUG_JOB
    ))
    conf["configjob"]["spec"] = {}

    # TODO: Variate the resource requests/limits between the task types
    conf["resource_limit_cpu"] = 1
    conf["resource_request_cpu"] = 1

    # Custom configurations depending on the task type:

    ############################################################################
    # task type: test
    ############################################################################
    if job_type == 'test':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_TEST
        conf["command"] = ["python", "task.py"]
        conf["configjob"]["spec"] = yaml.safe_load(template.render(
            taskDuration=int(params["time"])
        ))

    ############################################################################
    # task type: query
    ############################################################################
    elif job_type == 'query':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_QUERY
        conf["command"] = ["python3", "task.py"]
        quickQuery = "false"
        checkQuery = "false"
        try:
            if "quick" in params and params["quick"].lower() in ['true', '1', 'yes']:
                quickQuery = "true"
            if "check" in params and params["check"].lower() in ['true', '1', 'yes']:
                checkQuery = "true"
        except:
            pass
        conf["configjob"]["spec"] = yaml.safe_load(template.render(
            queryString=params["query"],
            quickQuery=quickQuery,
            checkQuery=checkQuery
        ))

    ############################################################################
    # task type: cutout
    ############################################################################
    elif job_type == 'cutout':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_CUTOUT
        conf["command"] = ["python3", "task.py"]

        # Process job configuration parameters
        #########################################
        # Initialize the job spec object
        spec = {
        'jobid': job_id,
        'usernm': username,
        'passwd': password,
        'tiledir': 'auto',
        'outdir': os.path.join('/home/worker/output/cutout', job_id),
        }

        # If RA/DEC are present in request parameters, ignore coadd if present.
        # If RA/DEC are not both present, assume
        if all(k in params for k in ("ra", "dec")):
            spec['ra'] = params["ra"]
            spec['dec'] = params["dec"]
        elif "coadd" in params:
            spec['coadd'] = params["coadd"]
        elif "positions" in params:
            spec['positions'] = params["positions"].encode('utf-8').decode('unicode-escape')
        else:
            status = STATUS_ERROR
            msg = 'Cutout job requires RA/DEC coordinates or Coadd IDs.'
            return status,msg,job_id
        if 'db' in params and params["db"].upper() in ['DESDR','DESSCI']:
            spec['db'] = params["db"].upper()
        else:
            status = STATUS_ERROR
            msg = 'Valid databases are DESDR and DESSCI'
            return status,msg,job_id

        if 'release' in params and params["release"].upper() in ['Y1A1','Y6A1','Y3A2','SVA1']:
            spec['release'] = params["release"].upper()
        else:
            status = STATUS_ERROR
            msg = "Valid releases are Y6A1,Y3A2,Y1A1,SVA1"
            return status,msg,job_id
        try:
            if "xsize" in params:
                spec['xsize'] = float("{:.2f}".format(float(params["xsize"])))
            if "ysize" in params:
                spec['ysize'] = float("{:.2f}".format(float(params["ysize"])))
        except:
            status = STATUS_ERROR
            msg = 'xsize and ysize must be numerical values'
            return status,msg,job_id
        # Set color strings from request parameters
        search_args = ['colors_rgb', 'colors_fits']
        for string_param in search_args:
            spec[string_param] = ''
        for string_param in list(set(search_args).intersection(set(params))):
            if isinstance(params[string_param], str) and len(params[string_param]) > 0:
                spec[string_param] = params[string_param]
        # Set default value if string is empty
        if len(spec['colors_fits']) < 1:
            spec['colors_fits'] = 'i'
        # Set boolean arguments from request parameters
        bool_param_found = False
        search_args = ['make_tiffs', 'make_fits', 'make_pngs', 'make_rgb_lupton', 'make_rgb_stiff', 'return_list']
        for bool_param in search_args:
            spec[bool_param] = False
        for bool_param in list(set(search_args).intersection(set(params))):
            spec[bool_param] = params[bool_param] == 'true' or str(params[bool_param]) == 'True'
            if spec[bool_param]:
                bool_param_found = True
        # If no booleans were set then no information was actually requested
        if not bool_param_found:
            status = STATUS_ERROR
            msg = 'No information requested.'
            return status,msg,job_id
        # If color images were requested, colors must be specified
        elif (spec['make_rgb_stiff'] or spec['make_rgb_lupton']) and len(spec['colors_rgb']) < 1:
            status = STATUS_ERROR
            msg = 'colors_rgb is required when requesting make_rgb_stiff or make_rgb_lupton'
            return status,msg,job_id
        # Filter and order color strings
        for string_param in ['colors_rgb', 'colors_fits']:
            if len(spec[string_param]) > 0:
                spec[string_param] = filter_and_order_colors(spec[string_param])
                # Error and return if no valid colors are specified
                if not spec[string_param]:
                    status = STATUS_ERROR
                    msg = 'Valid colors are y,z,i,r,g'
                    return status,msg,job_id
                elif string_param == 'colors_rgb' and len(spec[string_param].split(',')) != 3:
                    status = STATUS_ERROR
                    msg = 'Exactly three colors must be specified for colors_rgb'
                    return status,msg,job_id
        # Process Lupton RGB options
        search_args = ['rgb_minimum', 'rgb_stretch', 'rgb_asinh']
        for rgb_param in list(set(search_args).intersection(set(params))):
            try:
                spec[rgb_param] = float(params[rgb_param])
            except:
                status = STATUS_ERROR
                msg = 'rgb_minimum, rgb_stretch, rgb_asinh must be numerical values'
                return status,msg,job_id

        # Complete the job configuration by defining the `spec` node
        conf["configjob"]["spec"] = spec

    else:
        # Invalid job type
        job_id=''

    if job_id == '':
        status = STATUS_ERROR
        msg = 'Job type "{}" is not defined'.format(job_type)
        return status,msg,job_id
    else:
        msg = "Job:{} id:{} by:{}".format(job_type, job_id, username)
    try:
        kubejob.create_configmap(conf)
        kubejob_status, kubejob_msg = kubejob.create_job(conf)
        if kubejob_status == STATUS_ERROR:
            status = STATUS_ERROR
            msg = kubejob_msg
            return status,msg,job_id
    except Exception as e:
        status = STATUS_ERROR
        msg = str(e).strip()
        logger.error(msg)
        return status,msg,job_id
    try:
        JOBSDB.register_job(conf)
    except Exception as e:
        status = STATUS_ERROR
        msg = str(e).strip()
    return status,msg,job_id
