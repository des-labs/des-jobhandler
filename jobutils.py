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

    def get_table_names(self):
        return [
            'job',
            'query',
            'role',
            'session'
        ]

    def reinitialize_tables(self):
        self.open_db_connection()
        try:
            # Drop all existing database tables
            for table in self.get_table_names():
                self.cur.execute("DROP TABLE IF EXISTS {}".format(table))
            # Create the database tables from the schema file. Individual SQL
            # commands must be separated by the custom delimiter '#---'
            with open(os.path.join(os.path.dirname(__file__), "db_schema.sql")) as f:
                dbSchema = f.read()
            # Construct the database tables
            for sqlCommand in dbSchema.split('#---'):
                if len(sqlCommand) > 0 and not sqlCommand.isspace():
                    self.cur.execute(sqlCommand)
            # Initialize the database tables with info such as admin accounts
            # with open(os.path.join(os.path.dirname(__file__), "db_init", "db_init.yaml")) as f:
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
        except Exception as e:
            logger.error(str(e).strip())

        self.close_db_connection()

    def validate_apitoken(self, apitoken):
        self.open_db_connection()
        self.cur.execute(
            "SELECT id FROM `job` WHERE apitoken = '{}' LIMIT 1".format(
                apitoken)
        )
        # If there is a result, assume only one exists and return the record id, otherwise return None
        rowId = None
        for (id,) in self.cur:
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
                    "FROM `job` WHERE user = %s ORDER BY time_start DESC"
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
                if job_info == None:
                    request_status = 'error'
                    msg = 'Error retrieving all job statuses for user {}'.format(username)
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

        newJobSql = (
            "INSERT INTO `job` "
            "(user, type, name, uuid, status, apitoken, spec) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)"
        )
        newJobInfo = (
            conf["configjob"]["metadata"]["username"],
            conf["configjob"]["kind"],
            conf["configjob"]["metadata"]["name"],
            conf["configjob"]["metadata"]["jobId"],
            'init',
            conf["configjob"]["metadata"]["apiToken"],
            json.dumps(conf["configjob"]["spec"])
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
                response['msg'],
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
                "SELECT user,type,uuid from `job` WHERE id=%s"
            )
            selectJobInfo = (
                rowId,
            )
            self.cur.execute(selectJobSql, selectJobInfo)
            for (user, type, uuid) in self.cur:
                if job_status == "unknown":
                    logger.warning('Job {} completion report did not include a final status.'.format(uuid))
                conf = {"job": type}
                conf['namespace'] = get_namespace()
                conf["job_name"] = get_job_name(type, uuid, user)
                conf["cm_name"] = get_job_configmap_name(type, uuid, user)
                kubejob.delete_job(conf)
                if type == 'test':
                    updateQuerySql = (
                        "UPDATE `job` "
                        "SET msg=%s "
                        "WHERE id=%s"
                    )
                    updateQueryInfo = (
                        response['output'],
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
                        "SET token_value=%s, last_login=%s, password=%s "
                        "WHERE username=%s"
                    ),
                    (
                        token,
                        datetime.datetime.utcnow(),
                        ciphertext,
                        username,
                    )
                )
            else:
                self.cur.execute(
                    (
                        "INSERT INTO `session` "
                        "(username, token_value, last_login, password) "
                        "VALUES (%s, %s, %s, %s) "
                    ),
                    (
                        username,
                        token,
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
                    "SET token_value=%s, password=%s "
                    "WHERE username=%s"
                ),
                (
                    '',
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
    # Common configurations to all tasks types:
    username = params["username"].lower()
    job_type = params["job"]
    job_id = generate_job_id()
    conf = {}
    conf["job"] = job_type
    conf["namespace"] = get_namespace()
    conf["cm_name"] = get_job_configmap_name(conf["job"], job_id, username)
    conf["job_name"] = get_job_name(conf["job"], job_id, username)
    conf["host_network"] = envvars.HOST_NETWORK
    template = get_job_template(job_type)
    base_template = get_job_template_base()
    # Render the base YAML template for the job configuration data structure
    conf["configjob"] = yaml.safe_load(base_template.render(
        taskType=conf["job"],
        jobName=conf["job_name"],
        jobId=job_id,
        username=username,
        password=JOBSDB.get_password(username),
        logFilePath="./output/{}.log".format(conf["job_name"]),
        apiToken=secrets.token_hex(16),
        apiBaseUrl=envvars.API_BASE_URL,
        persistentVolumeClaim='{}{}'.format(envvars.PVC_NAME_BASE, conf["job"]),
        debug=False
    ))
    conf["configjob"]["spec"] = {}

    # TODO: Variate the resource requests/limits between the task types
    conf["resource_limit_cpu"] = 1
    conf["resource_request_cpu"] = 1

    # Custom configurations depending on the task type:
    if job_type == 'test':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_TEST
        conf["command"] = ["python", "task.py"]
        conf["configjob"]["spec"] = yaml.safe_load(template.render(
            taskDuration=int(params["time"])
        ))
    elif job_type == 'cutout':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_CUTOUT
        conf["command"] = ["python3", "task.py"]
    elif job_type == 'query':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_QUERY
        conf["command"] = ["python3", "task.py"]
        quickQuery = "false"
        try:
            if params["quick"].lower() in ['true', '1', 'yes']:
                quickQuery = "true"
        except:
            pass
        conf["configjob"]["spec"] = yaml.safe_load(template.render(
            queryString=params["query"],
            quickQuery=quickQuery
        ))
    else:
        # Invalid job type
        job_id=''

    if job_id == '':
        msg = 'Job type "{}" is not defined'.format(job_type)
    else:
        msg = "Job:{} id:{} by:{}".format(job_type, job_id, username)

    kubejob.create_configmap(conf)
    kubejob.create_job(conf)
    status = "ok"
    JOBSDB.register_job(conf)
    return status,msg,job_id
