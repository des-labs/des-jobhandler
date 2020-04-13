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
            for role in db_init['role']:
                self.cur.execute(
                    (
                        "INSERT INTO role "
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
            "SELECT id FROM job WHERE apitoken = '{}' LIMIT 1".format(
                apitoken)
        )
        # If there is a result, assume only one exists and return the record id, otherwise return None
        rowId = None
        for (id,) in self.cur:
            rowId = id
        self.close_db_connection()
        return rowId

    def register_job(self, conf):
        self.open_db_connection()

        newJobSql = (
            "INSERT INTO job "
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
        self.cur.execute(newJobSql, newJobInfo)
        self.close_db_connection()

    def update_job_start(self, rowId):
        self.open_db_connection()
        updateJobSql = (
            "UPDATE job "
            "SET status=%s, time_start=%s "
            "WHERE id=%s"
        )
        updateJobInfo = (
            'started',
            datetime.datetime.utcnow(),
            rowId
        )
        self.cur.execute(updateJobSql, updateJobInfo)
        error_msg = None
        if self.cur.rowcount != 1:
            error_msg = 'Error updating job record'
        self.close_db_connection()
        return error_msg

    def update_job_complete(self, rowId):
        self.open_db_connection()
        updateJobSql = (
            "UPDATE job "
            "SET status=%s, time_complete=%s "
            "WHERE id=%s"
        )
        updateJobInfo = (
            'complete',
            datetime.datetime.utcnow(),
            rowId
        )
        self.cur.execute(updateJobSql, updateJobInfo)
        error_msg = None
        if self.cur.rowcount != 1:
            error_msg = 'Error updating job record {}'.format(rowId)
        else:
            selectJobSql = (
                "SELECT user,job,name from job WHERE id=%s"
            )
            selectJobInfo = (
                rowId,
            )
            self.cur.execute(selectJobSql, selectJobInfo)
            for (user, job, name) in self.cur:
                conf = {"job": job}
                conf['namespace'] = get_namespace()
                conf["job_name"] = get_job_name(conf["job"], name, user)
                conf["cm_name"] = get_job_configmap_name(
                    conf["job"], name, user)
                kubejob.delete_job(conf)
        self.close_db_connection()
        return error_msg

    def session_login(self, username, token, ciphertext):
        self.open_db_connection()
        status = "ok"
        try:
            self.cur.execute(
                (
                    "SELECT id from session WHERE username=%s"
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
                        "UPDATE session "
                        "SET token_value=%s, token_refreshed=%s, password=%s "
                        "WHERE username=%s"
                    ),
                    (
                        token,
                        ciphertext,
                        datetime.datetime.utcnow(),
                        username,
                    )
                )
            else:
                self.cur.execute(
                    (
                        "INSERT INTO session "
                        "(username, token_value, token_refreshed, password) "
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

    def get_password(self, username):
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "SELECT id from account WHERE username=%s"
                ),
                (
                    username,
                )
            )
            account_id = None
            for (id,) in self.cur:
                account_id = id
            if isinstance(account_id, int):
                self.cur.execute(
                    (
                        "SELECT password from session WHERE account_id=%s"
                    ),
                    (
                        account_id,
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
        "jobconfig_spec.tpl.yaml"
    )
    with open(jobConfigTemplateFile) as f:
        templateText = f.read()
    return Template(templateText)

def submit_job(params):
    logger.info(params)
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

    # Custom configurations depending on the task type:
    if job_type == 'test':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_TEST
        conf["command"] = ["python", "task.py"]
        conf["configjob"]["spec"] = yaml.safe_load(template.render(
            taskDuration=int(params["time"])
        ))
    elif job_type == 'query':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_QUERY
        conf["command"] = ["python3", "task.py"]
        conf["configjob"]["spec"] = yaml.safe_load(template.render(
            queryString=params["query"]
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
