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
import shutil
import jira.client
import dbutils

STATUS_OK = 'ok'
STATUS_ERROR = 'error'

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
        self.db_schema_version = 13
        self.table_names = [
            'job',
            'query',
            'cutout',
            'role',
            'session',
            'meta',
            'help',
            'message',
            'message_read',
            'message_role',
            'user_preferences',
            'cron',
            'analytics',
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
                    # Only add the role if the record does not already exist.
                    self.cur.execute(
                        (
                            "SELECT id FROM `role` WHERE username = %s AND role_name = %s LIMIT 1"
                        ),
                        (
                            role["username"],
                            role["role_name"],
                        )
                    )
                    rowId = None
                    for (id,) in self.cur:
                        rowId = id
                    if rowId == None:
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
        request_status = STATUS_OK
        msg = ''
        job_info_list = []
        try:
            if job_id == "all":
                self.cur.execute(
                    (
                        "SELECT j.type, j.name, j.uuid, j.status, j.msg, j.time_start, j.time_complete, j.time_submitted, q.data, q.query, q.files, c.file_list, c.positions "
                        "FROM `job` j "
                        "LEFT JOIN `query` q "
                        "ON j.id = q.job_id "
                        "LEFT JOIN `cutout` c "
                        "ON j.id = c.job_id "
                        "WHERE j.user = %s AND j.deleted = 0 ORDER BY j.time_start DESC "
                    ),
                    (
                        username,
                    )
                )
                job_info = None
                for (type, name, uuid, status, msg, time_start, time_complete, time_submitted, data, query, files, file_list, positions) in self.cur:
                    job_info = {}
                    job_info["job_type"] = type
                    job_info["job_name"] = name
                    job_info["job_id"] = uuid
                    job_info["job_status"] = status
                    job_info["job_status_message"] = msg
                    job_info["job_time_start"] = time_start
                    job_info["job_time_complete"] = time_complete
                    job_info["job_time_submitted"] = time_submitted
                    job_info["data"] = {} if data is None else json.loads(data)
                    job_info["query"] = query
                    job_info["query_files"] = files
                    job_info["cutout_files"] = file_list
                    job_info["cutout_positions"] = positions
                    job_info_list.append(job_info)
            else:
                self.cur.execute(
                    (
                        "SELECT j.type, j.name, j.uuid, j.status, j.msg, j.time_start, j.time_complete, j.time_submitted, q.data, q.query, q.files, c.file_list, c.positions "
                        "FROM `job` j "
                        "LEFT JOIN `query` q "
                        "ON j.id = q.job_id "
                        "LEFT JOIN `cutout` c "
                        "ON j.id = c.job_id "
                        "WHERE j.user = %s AND j.uuid = %s AND j.deleted = 0 ORDER BY j.time_start DESC LIMIT 1"
                    ),
                    (
                        username,
                        job_id
                    )
                )
                job_info = None
                for (type, name, uuid, status, msg, time_start, time_complete, time_submitted, data, query, files, file_list, positions) in self.cur:
                    job_info = {}
                    job_info["job_type"] = type
                    job_info["job_name"] = name
                    job_info["job_id"] = uuid
                    job_info["job_status"] = status
                    job_info["job_status_message"] = msg
                    job_info["job_time_start"] = time_start
                    job_info["job_time_complete"] = time_complete
                    job_info["job_time_submitted"] = time_submitted
                    job_info["data"] = {} if data is None else json.loads(data)
                    job_info["query"] = query
                    job_info["query_files"] = files
                    job_info["cutout_files"] = file_list
                    job_info["cutout_positions"] = positions
                    job_info_list.append(job_info)
                if job_info == None:
                    request_status = 'error'
                    msg = 'Error retrieving job status for user {}, specific job_id {}'.format(username, job_id)
                    logger.error(msg)
        except:
            request_status = 'error'
            msg = 'Error retrieving job status for user {}, job_id {}'.format(username, job_id)
            logger.error(msg)
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
            "(user, type, name, uuid, status, apitoken, user_agent, email, msg, time_submitted) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
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
            '',
            datetime.datetime.utcnow(),
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
                for key in ['ra', 'dec', 'coadd', 'positions', 'xsize', 'ysize', 'rgb_minimum', 'rgb_stretch', 'rgb_asinh']:
                    if key in conf["configjob"]["spec"]:
                        opt_vals[key] = conf["configjob"]["spec"][key]
                    else:
                        opt_vals[key] = None
                self.cur.execute(
                    (
                        "INSERT INTO `cutout` "
                        "(`job_id`, `db`, `release`, `ra`, `dec`, `coadd`, `positions`, `make_tiffs`, "
                        "make_fits, make_pngs, make_rgb_lupton, make_rgb_stiff, "
                        "return_list, xsize, ysize, colors_rgb, colors_fits, "
                        "rgb_minimum, rgb_stretch, rgb_asinh) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    ),
                    (
                        self.cur.lastrowid,
                        conf["configjob"]["spec"]["db"],
                        conf["configjob"]["spec"]["release"],
                        opt_vals['ra'],
                        opt_vals['dec'],
                        opt_vals['coadd'],
                        opt_vals['positions'],
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
        try:
            if response['config']['kind'] == 'utility':
                conf = {"job": response['config']['kind']}
                conf['namespace'] = get_namespace()
                conf["job_name"] = response['config']['metadata']['job_name']
                conf["job_id"] = response['config']['metadata']['jobId']
                conf["cm_name"] = get_job_configmap_name(response['config']['kind'], response['config']['metadata']['jobId'], response['config']['metadata']['username'])
                kubejob.delete_job(conf)
                return error_msg
        except:
            pass
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
                job_name = name
                if job_status == "unknown":
                    logger.warning('Job {} completion report did not include a final status.'.format(job_id))
                conf = {"job": type}
                conf['namespace'] = get_namespace()
                conf["job_name"] = job_name
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
                try:
                    if len(email) > 4:
                        email_utils.send_note(user, job_id, job_name, email)
                except:
                    logger.error('Failed to send job complete email: {}/{}.'.format(user, job_id))
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

    def get_role_user_list(self, role_name):
        self.open_db_connection()
        users = []
        try:
            self.cur.execute(
                (
                    "SELECT username from `role` WHERE role_name=%s"
                ),
                (
                    role_name,
                )
            )
            for (username,) in self.cur:
                if username not in users:
                    users.append(username)
        except Exception as e:
            logger.error(str(e).strip())
        self.close_db_connection()
        return users

    def get_user_roles(self, username):
        self.open_db_connection()
        # Ensure that all users have the default role
        roles = ['default']
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
                if isinstance(role_name, str) and not role_name in roles:
                    roles.append(role_name)
        except Exception as e:
            logger.error(str(e).strip())
        self.close_db_connection()
        return roles

    def get_all_user_roles_and_help_requests(self):
        self.open_db_connection()
        users = {}
        users_array = []
        try:
            self.cur.execute("SELECT username, role_name from `role`")
            for (username, role_name,) in self.cur:
                # Assume that if the user is in this table, it must have at least one associated role
                if username in users:
                    users[username]['roles'].append(role_name)
                else:
                    users[username] = {
                    'roles': [role_name],
                    'help_requests': []
                    }
            # Ensure that all users have the default role
            if not 'default' in users[username]['roles']:
                users[username]['roles'].append('default')
            self.cur.execute("SELECT user, jira_issue from `help` WHERE resolved = 0 ")
            for (user, jira_issue,) in self.cur:
                if user in users:
                    users[user]['help_requests'].append(jira_issue)
                else:
                    users[user] = {
                    # Ensure that all users have the default role
                    'roles': ['default'],
                    'help_requests': [jira_issue]
                    }
            for username in users:
                users_array.append({
                    'username': username,
                    'roles': users[username]['roles'],
                    'help_requests': users[username]['help_requests']
                })
        except Exception as e:
            logger.error(str(e).strip())
        self.close_db_connection()
        return users_array

    def sync_help_requests_with_jira(self):
        error_msg = ''
        self.open_db_connection()
        try:
            self.cur.execute("SELECT id, user, jira_issue from `help` ")
            # Compile the records in an array before executing more SQL commands to empty the cursor
            jira_issues = []
            for (id, user, jira_issue,) in self.cur:
                jira_issues.append({
                    'id': id,
                    'user': user,
                    'jira_issue': jira_issue
                })
            for x in jira_issues:
                try:
                    issue = JIRA_API.issue(x['jira_issue'])
                    # View the fields and their values for the issue:
                    # for field_name in issue.raw['fields']:
                    #     logger.info("Field: {}\nValue: {}".format(field_name, issue.raw['fields'][field_name]))
                    if issue.fields.resolution == None:
                        self.cur.execute("UPDATE `help` SET resolved = 0 WHERE id = {}".format(x['id']))
                    else:
                        self.cur.execute("UPDATE `help` SET resolved = 1 WHERE id = {}".format(x['id']))
                except Exception as e:
                    error_msg = '{}\n{}'.format(error_msg, str(e).strip())
                    logger.error(error_msg)
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

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

    def mark_job_deleted(self, job_id):
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

    def delete_job_files(self, job_id, username):
        status = STATUS_OK
        error_msg = ''
        self.open_db_connection()
        try:
            job_info_list, request_status, status_msg = JOBSDB.job_status(username, job_id)
            if request_status == STATUS_ERROR:
                status = STATUS_ERROR
                error_msg = status_msg
            else:
                delete_path = os.path.join('/jobfiles', username, job_info_list[0]['job_type'], job_id)
                if os.path.isdir(delete_path):
                    shutil.rmtree(delete_path)
                archive_file = os.path.join('/jobfiles', username, job_info_list[0]['job_type'], '{}.tar.gz'.format(job_id))
                if os.path.isfile(archive_file):
                    os.remove(archive_file)
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return [status, error_msg]

    def rename_job(self, job_id, job_name):
        error_msg = ''
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "UPDATE `job` SET `name`=%s WHERE `uuid` = %s"
                ),
                (
                    job_name,
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

    def update_user_roles(self, username, new_roles):
        error_msg = ''
        self.open_db_connection()
        try:
            for role in new_roles:
                # Sanitize input role name to enforce only lowercase letters
                if role != re.sub(r'([^a-z])', '', role.lower()):
                    self.close_db_connection()
                    error_msg = 'Role names may only consist of lowercase letters.'
                    return error_msg
            self.cur.execute(
                (
                    "DELETE FROM `role` WHERE `username` = %s"
                ),
                (
                    username,
                )
            )
            for role in new_roles:
                # Sanitize input role name to enforce only lowercase letters
                role = re.sub(r'([^a-z])', '', role.lower())
                self.cur.execute(
                    (
                        "INSERT INTO `role` "
                        "(username, role_name) "
                        "VALUES (%s, %s)"
                    ),
                    (
                        username,
                        role,
                    )
                )
                if self.cur.rowcount != 1:
                    error_msg = 'Error adding user role: {}'.format(role)
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def set_user_roles(self, username, new_roles):
        error_msg = ''
        self.open_db_connection()
        try:
            for role in new_roles:
                # Sanitize input role name to enforce only lowercase letters
                if role != re.sub(r'([^a-z])', '', role.lower()):
                    self.close_db_connection()
                    error_msg = 'Role names may only consist of lowercase letters.'
                    return error_msg
            self.cur.execute(
                (
                    "SELECT id FROM `role` WHERE `username` = %s LIMIT 1"
                ),
                (
                    username,
                )
            )
            uid = None
            for (id,) in self.cur:
                uid = id
            if uid != None:
                error_msg = 'User already exists: {}'.format(username)
            else:
                for role in new_roles:
                    # Sanitize input role name to enforce only lowercase letters
                    role = re.sub(r'([^a-z])', '', role.lower())
                    self.cur.execute(
                        (
                            "INSERT INTO `role` "
                            "(username, role_name) "
                            "VALUES (%s, %s)"
                        ),
                        (
                            username,
                            role,
                        )
                    )
                    if self.cur.rowcount != 1:
                        error_msg = 'Error adding user role: {}'.format(role)
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def reset_user_roles(self, username):
        error_msg = ''
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "DELETE FROM `role` WHERE `username` = %s"
                ),
                (
                    username,
                )
            )
            if self.cur.rowcount < 1:
                error_msg = 'Error deleting user: {}'.format(username)
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def process_help_request(self, form_data):
        error_msg = ''
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "INSERT INTO `help` "
                    "(user, firstname, lastname, email, message, topics, othertopic, jira_issue) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                ),
                (
                    form_data['username'],
                    form_data['firstname'],
                    form_data['lastname'],
                    form_data['email'],
                    form_data['message'],
                    json.dumps(form_data['topics']),
                    form_data['othertopic'],
                    form_data['jira_issue_number'],
                )
            )
            if self.cur.rowcount < 1:
                error_msg = 'Error adding help form to DB'
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def create_notification(self, title, body, roles, time):
        error_msg = ''
        self.open_db_connection()
        try:
            # Deduplicate input roles list and ensure default is included
            roles_dedup = []
            for role_name in roles:
                if role_name not in roles_dedup:
                    roles_dedup.append(role_name)
            roles = roles_dedup
            if roles == []:
                roles = ['default']
            self.cur.execute(
                (
                    "INSERT INTO `message` "
                    "(title, body, date) "
                    "VALUES (%s, %s, %s)"
                ),
                (
                    title,
                    body,
                    time,
                )
            )
            if self.cur.rowcount < 1 or not self.cur.lastrowid:
                error_msg = 'Error adding message to message database table'
            else:
                message_id = self.cur.lastrowid
                for role_name in roles:
                    self.cur.execute(
                        (
                            "INSERT INTO `message_role` "
                            "(message_id, role_name) "
                            "VALUES (%s, %s)"
                        ),
                        (
                            message_id,
                            role_name
                        )
                    )
                    if not self.cur.lastrowid:
                        error_msg = 'Error adding message to message_role database table'
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def delete_notification(self, message_id):
        error_msg = ''
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "DELETE FROM `message` WHERE id = %s"
                ),
                (
                    message_id,
                )
            )
            if self.cur.rowcount < 1:
                error_msg = 'Error deleting message from message database table'
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def edit_notification(self, message_id, title, body, roles):
        error_msg = ''
        self.open_db_connection()
        try:
            # Deduplicate input roles list and ensure default is included
            roles_dedup = []
            for role_name in roles:
                if role_name not in roles_dedup:
                    roles_dedup.append(role_name)
            roles = roles_dedup
            if roles == []:
                roles = ['default']
            self.cur.execute(
                (
                    "UPDATE `message` SET title = %s, body = %s WHERE id = %s "
                ),
                (
                    title,
                    body,
                    message_id
                )
            )
            # Delete the existing roles for the message
            self.cur.execute(
                (
                    "DELETE FROM `message_role` WHERE message_id = %s "
                ),
                (
                    message_id,
                )
            )
            # Insert the new roles for the message
            for role_name in roles:
                self.cur.execute(
                    (
                        "INSERT INTO `message_role` "
                        "(message_id, role_name) "
                        "VALUES (%s, %s)"
                    ),
                    (
                        message_id,
                        role_name
                    )
                )
                if not self.cur.lastrowid:
                    error_msg = 'Error adding message to message_role database table'
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def get_notifications(self, message, username, roles):
        error_msg = ''
        messages = []
        self.open_db_connection()
        try:
            # Deduplicate input roles list and ensure default is included
            roles_dedup = ['default']
            roles_sql = '("{}"'.format(roles_dedup[0])
            for role_name in roles:
                if role_name not in roles_dedup:
                    roles_dedup.append(role_name)
                    roles_sql = '{},"{}"'.format(roles_sql, role_name)
            roles = roles_dedup
            roles_sql = '{})'.format(roles_sql)
            messages_without_roles = []
            if message == 'all':
                # Get message IDs visible to each of the user's roles
                sql_query = '''
                    SELECT t1.id, t1.date, t1.title, t1.body
                    FROM `message` t1
                    INNER JOIN `message_role` t2
                    ON t2.role_name IN {} AND t1.id = t2.message_id
                '''.format(roles_sql)
                self.cur.execute(sql_query)
                for (id, date, title, body,) in self.cur:
                    new_message = {
                        'id': id,
                        'time': date,
                        'title': title,
                        'body': body
                    }
                    if new_message not in messages_without_roles:
                        messages_without_roles.append(new_message)
                for msg in messages_without_roles:
                    self.cur.execute(
                        (
                            "SELECT role_name FROM `message_role` WHERE message_id = %s"
                        ),
                        (
                            msg['id'],
                        )
                    )
                    msg['roles'] = []
                    for (role_name,) in self.cur:
                        msg['roles'].append(role_name)
                    messages.append(msg)
            elif message == 'new':
                # Get message IDs visible to each of the user's roles
                sql_query = '''
                    SELECT t1.id, t1.date, t1.title, t1.body
                    FROM `message` t1
                    INNER JOIN `message_role` t2
                    ON t2.role_name IN {} AND t1.id = t2.message_id
                '''.format(roles_sql)
                self.cur.execute(sql_query)
                all_messages = []
                for (id, date, title, body,) in self.cur:
                    all_messages.append({
                        'id': id,
                        'date': date,
                        'title': title,
                        'body': body
                    })
                for msg in all_messages:
                    self.cur.execute(
                        (
                            "SELECT id FROM `message_read` WHERE message_id = %s and username = %s "
                        ),
                        (
                            msg['id'],
                            username
                        )
                    )
                    rowId = None
                    for (id,) in self.cur:
                        rowId = id
                    if rowId == None:
                        new_message = {
                            'id':  msg['id'],
                            'time':  msg['date'],
                            'title': msg['title'],
                            'body':  msg['body'],
                        }
                        if new_message not in messages:
                            messages.append(new_message)
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return messages, error_msg

    def mark_notification_read(self, message_id, username):
        error_msg = ''
        self.open_db_connection()
        try:
            # TODO: Validate message_id to ensure it exists in `message` table
            # Only add the role if the record does not already exist.
            self.cur.execute(
                (
                    "SELECT id FROM `message_read` WHERE username = %s AND message_id = %s LIMIT 1"
                ),
                (
                    username,
                    message_id
                )
            )
            rowId = None
            for (id,) in self.cur:
                rowId = id
            if rowId == None:
                self.cur.execute(
                    (
                        "INSERT INTO `message_read` "
                        "(username, message_id) "
                        "VALUES (%s, %s)"
                    ),
                    (
                        username,
                        message_id
                    )
                )
                if not self.cur.lastrowid:
                    error_msg = 'Error marking message read in message_read database table'
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def get_user_preference(self, preference, username):
        # preference is either 'all' to get all preferences as an object, or it is the name
        # of a specific preference key, to get the individual preference value
        error_msg = ''
        value = {}
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "SELECT id, preferences FROM `user_preferences` WHERE username = %s LIMIT 1"
                ),
                (
                    username,
                )
            )
            rowId = None
            for (id, preferences,) in self.cur:
                rowId = id
                preferences = {} if preferences is None else json.loads(preferences)
            # No user preferences have been set yet
            if rowId != None:
                # User preferences exist
                if preference == 'all':
                    value = preferences
                else:
                    value = preferences[preference]
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return value, error_msg

    def set_user_preference(self, preference, value, username):
        error_msg = ''
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "SELECT id, preferences FROM `user_preferences` WHERE username = %s LIMIT 1"
                ),
                (
                    username,
                )
            )
            rowId = None
            for (id, preferences,) in self.cur:
                rowId = id
                preferences = {} if preferences is None else json.loads(preferences)
            # No user preferences have been set yet
            if rowId == None:
                preferences = {}
                preferences[preference] = value
                self.cur.execute(
                    (
                        "INSERT INTO `user_preferences` "
                        "(username, preferences) "
                        "VALUES (%s, %s)"
                    ),
                    (
                        username,
                        json.dumps(preferences),
                    )
                )
                if not self.cur.lastrowid:
                    error_msg = 'Error setting user preference'
            # User preferences exist, so they must be updated.
            else:
                preferences[preference] = value
                self.cur.execute(
                    (
                        "UPDATE `user_preferences` SET preferences = %s "
                        "WHERE username = %s "
                    ),
                    (
                        json.dumps(preferences),
                        username,
                    )
                )
                if not self.cur.lastrowid:
                    error_msg = 'Error setting user preference'
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def cron_get_all(self):
        error_msg = ''
        cronjobs = []
        self.open_db_connection()
        try:
            self.cur.execute("SELECT name, period, last_run FROM `cron` WHERE enabled = 1")
            for (name, period, last_run) in self.cur:
                cronjobs.append({
                    'name': name,
                    'period': period,
                    'last_run': last_run
                })
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return cronjobs, error_msg

    def cron_update_run_time(self, name, datetime):
        error_msg = ''
        self.open_db_connection()
        try:
            self.cur.execute(
                ("UPDATE `cron` SET `last_run` = %s WHERE name = %s" ),
                (
                    datetime,
                    name
                )
            )
            if self.cur.rowcount != 1:
                error_msg = 'Error updating cron record "{}".'.format(name)
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return error_msg

    def analytics_record_api(self, request_path, current_time, user_agent, remote_ip):
        status = STATUS_OK
        error_msg = ''
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "INSERT INTO `analytics` "
                    "(request_path, call_time, user_agent, remote_ip) "
                    "VALUES (%s, %s, %s, %s)"
                ),
                (
                    request_path, 
                    current_time, 
                    user_agent,
                    remote_ip,
                )
            )
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
        self.close_db_connection()
        return status, error_msg


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
        conf["db"] = params['db']
        conf["namespace"] = get_namespace()
        conf["cm_name"] = get_job_configmap_name(job_type, job_id, username)
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

    if job_type == 'utility':
        try:
            logFilePath = "./output/{}_{}_{}.log".format(job_type, params['action'], params['job-id'])
        except:
            status = STATUS_ERROR
            msg = 'Invalid options for utility job type'
            return status,msg,''
    else:
        logFilePath = "./output/{}/{}.log".format(conf["job"], job_id)

    # Render the base YAML template for the job configuration data structure
    conf["configjob"] = yaml.safe_load(base_template.render(
        taskType=conf["job"],
        jobName=job_id,
        job_name=conf['job_name'],
        jobId=job_id,
        username=username,
        password=password,
        database=conf['db'],
        logFilePath=logFilePath,
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
    # task type: utility
    ############################################################################
    elif job_type == 'utility':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_UTILITY
        try:
            action = params['action']
            delete_path = ''
            conf["command"] = ["python", "task.py"]
            if action == 'delete_job_files':
                # Get the type of job in order to construct the path to be deleted
                job_info_list, request_status, status_msg = JOBSDB.job_status(username, params['job-id'])
                if request_status == STATUS_ERROR:
                    status = STATUS_ERROR
                    msg = status_msg
                else:
                    delete_path = os.path.join('/home/worker/output', job_info_list[0]['job_type'], params['job-id'])
                    conf["configjob"]["spec"] = yaml.safe_load(template.render(
                        action=action,
                        delete_paths=[delete_path]
                    ))
            else:
                status = STATUS_ERROR
                msg = 'Supported actions include "delete_job_files"'
                return status,msg,job_id

        except:
            status = STATUS_ERROR
            msg = 'Invalid options for utility job type'
            return status,msg,job_id
    ############################################################################
    # task type: query
    ############################################################################
    elif job_type == 'query':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_QUERY
        conf["command"] = ["python3", "task.py"]
        quickQuery = "false"
        checkQuery = "false"
        compression = "false"
        try:
            if "quick" in params and params["quick"].lower() in ['true', '1', 'yes']:
                quickQuery = "true"
            if "check" in params and params["check"].lower() in ['true', '1', 'yes']:
                checkQuery = "true"
            if "compression" in params and params["compression"].lower() in ['true', '1', 'yes']:
                compression = "true"
        except:
            pass
        try:
            conf["configjob"]["spec"] = yaml.safe_load(template.render(
                queryString=params["query"],
                fileName=params["filename"],
                quickQuery=quickQuery,
                checkQuery=checkQuery,
                compression=compression
            ))
        except:
            status = STATUS_ERROR
            msg = 'query and filename are required'
            return status,msg,job_id

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
        # Register the job in the database unless it is a utility job
        if job_type != 'utility':
            JOBSDB.register_job(conf)
    except Exception as e:
        status = STATUS_ERROR
        msg = str(e).strip()
    return status,msg,job_id
