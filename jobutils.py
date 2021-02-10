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
from des_tasks.cutout.worker.bulkthumbs import validate_user_defaults as validate_cutout_user_defaults
from des_tasks.cutout.worker.bulkthumbs import validate_positions_table as validate_cutout_positions_table

import numpy as np

STATUS_OK = 'ok'
STATUS_ERROR = 'error'
# TODO: Replace this global hard-coded variable with input configuration
MAX_SIZE_IN_ARCMINUTES = 12.0

log_format = "%(asctime)s  %(name)8s  %(levelname)5s  %(message)s"
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.FileHandler("test.log"), logging.StreamHandler()],
    format=log_format,
)
logger = logging.getLogger(__name__)

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
        self.db_schema_version = 18
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
            'job_renewal',
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
                uuid_criterion_sql = ''
                sql_values = (username,)
            else:
                uuid_criterion_sql = ' AND j.uuid = %s '
                sql_values = (username, job_id)
            sql = '''
            SELECT j.type, j.name, j.uuid, j.status, j.msg, j.time_start, j.time_complete, j.time_submitted, q.data, q.query, q.files, c.file_list, c.summary as cutout_summary, c.positions, r.renewal_token, r.expiration_date
            FROM `job` j 
            LEFT JOIN `query` q 
            ON j.id = q.job_id 
            LEFT JOIN `cutout` c 
            ON j.id = c.job_id 
            LEFT JOIN `job_renewal` r 
            ON j.id = r.job_id 
            WHERE j.user = %s {} AND j.deleted = 0 ORDER BY j.time_start DESC 
            '''.format(uuid_criterion_sql)
            self.cur.execute(sql, sql_values)
            job_info = None
            for (type, name, uuid, status, msg, time_start, time_complete, time_submitted, data, query, files, file_list, cutout_summary, positions, renewal_token, expiration_date) in self.cur:
                job_info = {}
                job_info["job_type"] = type
                job_info["job_name"] = name
                job_info["job_id"] = uuid
                job_info["job_status"] = status
                job_info["job_status_message"] = msg
                job_info["job_time_start"] = "" if time_start is None else time_start
                job_info["job_time_complete"] = "" if time_complete is None else time_complete
                job_info["job_time_submitted"] = "" if time_submitted is None else time_submitted
                job_info["data"] = {} if data is None else json.loads(data)
                job_info["query"] = query
                job_info["query_files"] = [] if files is None else json.loads(files)
                job_info["cutout_files"] = [] if file_list is None else json.loads(file_list)
                job_info["cutout_summary"] = {} if cutout_summary is None else json.loads(cutout_summary)
                job_info["cutout_positions"] = "" if positions is None else positions
                job_info["renewal_token"] = "" if renewal_token is None else renewal_token
                job_info["expiration_date"] = "" if expiration_date is None else expiration_date
                if job_id != "all" or job_info["job_type"] != 'query' or (isinstance(data, str) and data == '{}'):
                    job_info_list.append(job_info)
            if job_id != "all" and not job_info_list:
                request_status = STATUS_ERROR
                msg = 'Error retrieving job status for user {}, specific job_id {}'.format(username, job_id)
                logger.error(msg)
        except:
            request_status = STATUS_ERROR
            msg = 'Error retrieving job status for user {}, job_id {}'.format(username, job_id)
            logger.error(msg)
        self.close_db_connection()
        return [job_info_list, request_status, msg]

    def job_list(self, username):
        self.open_db_connection()
        request_status = STATUS_OK
        msg = ''
        job_info_list = []
        try:
            # SELECT uuid as job_id, status as job_status, type as job_type, name as job_name
            # FROM `job`
            # WHERE `user` = %s AND `deleted` = 0 AND (data IS NULL and 
            # ORDER BY `time_start` DESC 
            sql = '''
            SELECT j.uuid as job_id, j.status as job_status, j.type as job_type, j.name as job_name, q.data
            FROM `job` j 
            LEFT JOIN `query` q 
            ON j.id = q.job_id 
            WHERE j.user = %s AND j.deleted = 0 ORDER BY j.time_start DESC 
            '''
            self.cur.execute(sql, (username,))
            job_info = None
            for (job_id, job_status, job_type, job_name, data) in self.cur:
                job_info = {}
                job_info["job_id"] = job_id
                job_info["job_status"] = job_status
                job_info["job_type"] = job_type
                job_info["job_name"] = job_name
                if job_type != 'query' or (isinstance(data, str) and data == '{}'):
                    job_info_list.append(job_info)
                    # logger.info('Including(data type: {}) {}'.format(type(data), job_info))
                # else:
                #     logger.info('Skipping (data type: {}) {}\nData: {}'.format(type(data), job_info, data))
        except:
            request_status = STATUS_ERROR
            msg = 'Error retrieving job list for user {}'.format(username)
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
            conf['configjob']["metadata"]["username"],
            conf['configjob']["kind"],
            conf['configjob']["metadata"]["job_name"],
            conf['configjob']["metadata"]["jobId"],
            'init',
            conf['configjob']["metadata"]["apiToken"],
            conf["user_agent"],
            email,
            '',
            datetime.datetime.utcnow(),
        )
        self.cur.execute(newJobSql, newJobInfo)
        if self.cur.lastrowid:
            if conf['configjob']["kind"] == 'query':
                newQuerySql = (
                    "INSERT INTO `query` "
                    "(job_id, query, files, sizes, data) "
                    "VALUES (%s, %s, %s, %s, %s)"
                )
                newQueryInfo = (
                    self.cur.lastrowid,
                    conf['configjob']['spec']["inputs"]["queryString"],
                    '[]',
                    '[]',
                    '{}',
                )
                self.cur.execute(newQuerySql, newQueryInfo)
            elif conf['configjob']["kind"] == 'test':
                # TODO: Add test table row associated with test task
                logger.info('Created new job of type "test"')
            elif conf['configjob']["kind"] == 'cutout':
                opt_vals = {}
                opt_params = [
                    'positions', 
                    'make_fits', 
                    'make_rgb_stiff', 
                    'make_rgb_lupton', 
                    'xsize', 
                    'ysize', 
                    'colors_fits', 
                    'rgb_stiff_colors', 
                    'rgb_lupton_colors', 
                    'rgb_minimum', 
                    'rgb_stretch', 
                    'rgb_asinh',
                    'discard_fits_files',
                ]
                for key in opt_params:
                    if key in conf['configjob']['spec']:
                        opt_vals[key] = conf['configjob']['spec'][key]
                    else:
                        opt_vals[key] = None
                self.cur.execute(
                    (
                        '''
                        INSERT INTO `cutout` 
                        (
                            `job_id`, 
                            `db`, 
                            `release`, 
                            `positions`, 
                            `make_fits`,
                            `make_rgb_stiff`,
                            `make_rgb_lupton`,
                            `xsize`, 
                            `ysize`, 
                            `colors_fits`, 
                            `rgb_stiff_colors`, 
                            `rgb_lupton_colors`, 
                            `rgb_minimum`, 
                            `rgb_stretch`, 
                            `rgb_asinh`,
                            `discard_fits_files`
                        ) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        '''
                    ),
                    (
                        self.cur.lastrowid,
                        conf['configjob']['spec']['db'],
                        conf['configjob']['spec']['release'],
                        conf['configjob']['spec']['positions'],
                        opt_vals['make_fits'],
                        opt_vals['make_rgb_stiff'],
                        opt_vals['make_rgb_lupton'],
                        opt_vals['xsize'],
                        opt_vals['ysize'],
                        opt_vals['colors_fits'],
                        opt_vals['rgb_stiff_colors'],
                        opt_vals['rgb_lupton_colors'],
                        opt_vals['rgb_minimum'],
                        opt_vals['rgb_stretch'],
                        opt_vals['rgb_asinh'],
                        opt_vals['discard_fits_files'],
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

    def count_pending_jobs(self, username):
        num_pending_jobs = 0
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "SELECT `status` FROM `job` where `user` = %s"
                ),
                (
                    username,
                )
            )
            for (status,) in self.cur:
                if status not in ['success', 'failure', 'unknown']:
                    num_pending_jobs += 1
        except Exception as e:
            logger.error(str(e).strip())
        self.close_db_connection()
        return num_pending_jobs

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
                job_name = name
                if job_status == "unknown":
                    logger.warning('Job {} completion report did not include a final status.'.format(job_id))
                conf = {"job": type}
                conf['namespace'] = get_namespace()
                conf["job_name"] = job_name
                conf["job_id"] = job_id
                conf["cm_name"] = get_job_configmap_name(type, job_id, user)
                if 'synchronous' not in response or response['synchronous'] != True:
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
                            "SET file_list=%s, file_size=%s, file_number=%s , summary=%s "
                            "WHERE job_id=%s"
                        ),
                        (
                            json.dumps(response["files"]),
                            str(response["sizes"]),
                            len(response["files"]),
                            json.dumps(response["summary"]),
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
        status = STATUS_OK
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
            status = STATUS_ERROR
        self.close_db_connection()
        return status

    def session_logout(self, username):
        # This function assumes the logout action is already authorized
        self.open_db_connection()
        status = STATUS_OK
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
            status = STATUS_ERROR
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
            # # Search for issues in DESHELP
            # jql = '''summary ~ "Help with DESDM account" 
            #     and project = "DESHELP" 
            #     and (text ~ "Reset my passwords" | text ~ "Forgot DB credentials") 
            #     and status = "Open"
            # '''
            # deshelpIssues = []
            # try:
            #     for issue in JIRA_API.search_issues(jql):
            #         deshelpIssues.append(issue.key)
            #     logger.info('password reset issues: \n{}'.format(deshelpIssues))
            # except Exception as e:
            #     logger.error(str(e).strip())
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

    def renew_job(self, renewal_token, job_ttl=envvars.DESACCESS_JOB_FILES_LIFETIME):
        status = STATUS_OK
        msg = ''
        valid = True
        self.open_db_connection()
        try:
            # Validate the submitted renewal token
            status, msg, job_table_id, username = JOBSDB.validate_renewal_token(renewal_token)
            if status != STATUS_OK or not isinstance(job_table_id, int):
                valid = False
                self.close_db_connection()
                return status, msg, valid
            # Record the job renewal

            sql = '''
            SELECT `job_id`, `renewals_used`, `renewals_left`, `expiration_date` FROM `job_renewal`
            WHERE `renewal_token` = %s LIMIT 1
            '''
            self.cur.execute(sql, (renewal_token,))
            results = self.cur.fetchall()
            for (job_id, renewals_used, renewals_left, expiration_date) in results:
                # If there are no more renewals available, return a failure message
                if renewals_left < 1:
                    status = STATUS_ERROR
                    msg = 'No more renewals are allowed for this job.'
                    self.close_db_connection()
                    return status, msg, valid
                # Update the job_renewal information by updating the number of used/left renewals and advancing the expiration date
                sql = '''
                UPDATE `job_renewal` 
                SET `renewals_used` = %s, `renewals_left` = %s, `renewal_token` = %s, `expiration_date` = %s
                WHERE `job_id` = %s 
                '''
                self.cur.execute(sql, (
                    renewals_used + 1,
                    renewals_left - 1,
                    generate_uuid() if renewals_left > 1 else None,
                    expiration_date + datetime.timedelta(0, job_ttl),
                    job_table_id,
                ))
                if self.cur.rowcount != 1:
                    status = STATUS_ERROR
                    msg = 'Error updating job renewal for job table row id "{}" in job_renewal database table'.format(job_table_id)
                    self.close_db_connection()
                    return status, msg, valid
        except Exception as e:
            status = STATUS_ERROR
            msg = str(e).strip()
            logger.error(msg)
        self.close_db_connection()
        return status, msg, valid

    def validate_renewal_token(self, renewal_token):
        status = STATUS_OK
        msg = ''
        job_table_id = None
        username = None
        self.open_db_connection()
        try:
            sql = '''
            SELECT r.job_id as job_row_id, j.user as job_username FROM `job_renewal` r 
            LEFT JOIN `job` j
            ON r.job_id = j.id
            WHERE r.renewal_token = %s LIMIT 1
            '''
            self.cur.execute(sql, (renewal_token,))
            for (job_row_id, job_username,) in self.cur:
                job_table_id = job_row_id
                username = job_username
            if not job_table_id:
                msg = 'Invalid job renewal token'
        except Exception as e:
            status = STATUS_ERROR
            msg = str(e).strip()
            logger.error(msg)
        self.close_db_connection()
        return status, msg, job_table_id, username

    def prune_job_files(self, USER_DB_MANAGER, job_ttl, job_warning_period, current_time):
        status = STATUS_OK
        msg = ''
        # logger.info('job_ttl: {}, job_warning_period: {}'.format(job_ttl, job_warning_period))
        # Enforce a positive finite lifetime and warning period.
        if job_ttl <= 0 or job_warning_period <= 0 or job_ttl - job_warning_period <= 0:
            status = STATUS_ERROR
            msg = 'Invalid job lifetime and/or warning period specified. Skipping job file pruning...'
            return status, msg
        self.open_db_connection()
        try:
            sql = '''
            SELECT j.id as job_row_id, j.uuid as job_id, j.user as username, j.type as job_type, j.name as job_name, j.time_complete, 
                   r.id as renewal_row_id, r.renewals_used, r.renewals_left, r.expiration_date, r.renewal_token
            FROM `job` j
            LEFT JOIN `job_renewal` r
            ON j.id = r.job_id
            WHERE j.deleted = 0 AND j.time_complete > 0
            '''
            self.cur.execute(sql)
            completed_jobs = self.cur.fetchall()
            for (job_row_id, job_id, username, job_type, job_name, time_complete, renewal_row_id, renewals_used, renewals_left, expiration_date, renewal_token) in completed_jobs:
                # If the expiration_date is None, then the job_renewal record needs to be added. Otherwise,
                # assume all columns have valid information
                if not renewal_row_id:
                    renewals_used = 0
                    renewals_left = envvars.DESACCESS_JOB_FILES_MAX_RENEWALS
                    expiration_date = time_complete + datetime.timedelta(0, job_ttl)
                    renewal_token = generate_uuid()
                    # logger.info('job_renewal record missing for job {}. Creating...'.format(job_row_id))
                    sql = '''
                    INSERT INTO `job_renewal` 
                    (`job_id`, `renewals_used`, `renewals_left`, `expiration_date`, `renewal_token`)
                    VALUES (%s, %s, %s, %s, %s)
                    '''
                    self.cur.execute(sql, (
                        job_row_id,
                        renewals_used,
                        renewals_left,
                        expiration_date,
                        renewal_token,
                    ))
                    if not self.cur.lastrowid:
                        logger.error('Error adding record to job_renewal table for job {}'.format(job_row_id))
                warning_date = expiration_date - datetime.timedelta(0, job_warning_period)
                logger.info('Job "{}" has been renewed {} times. The expiration date is currently "{}"'.format(job_id, renewals_used, expiration_date))
                #
                # Job file storage has expired
                #
                if current_time > expiration_date:
                    # Prune the job files
                    # logger.info('Deleting any existing renewal records...')
                    sql = '''
                    DELETE FROM `job_renewal` WHERE `job_id` = %s
                    '''
                    self.cur.execute(sql, (job_row_id,))
                    # logger.info('Deleting files from job "{}"'.format(job_id))
                    # TODO: Reduce redundancy of this code with the API handler function in `main.py`
                    conf = {
                        "job_type": job_type,
                        "namespace": get_namespace(),
                        "job_name": job_name,
                        "job_id": job_id,
                        "cm_name": get_job_configmap_name(job_type, job_id, username),
                    }
                    # Delete the k8s Job if it is still running
                    kubejob.delete_job(conf)
                    # Delete the job files on disk
                    status, msg = JOBSDB.delete_job_files(job_id, username)
                    if status == STATUS_OK:
                        # Mark the job deleted in the JobHandler database
                        msg = JOBSDB.mark_job_deleted(job_id)
                        if msg != '':
                            status = STATUS_ERROR
                            msg = 'Error marking job "{}" as deleted during periodic pruning.'.format(job_id)
                            logger.error(msg)
                            self.close_db_connection()
                            return status, msg
                        else:
                            logger.info('Job "{}" files deleted in periodic pruning.'.format(job_id))
                    else:
                        status = STATUS_ERROR
                        msg = 'Error deleting files for job "{}" during periodic pruning.'.format(job_id)
                        logger.error(msg)
                        self.close_db_connection()
                        return status, msg
                #
                # Job file storage will expire within the warning time period
                #
                elif current_time > warning_date and renewals_left > 0:
                    # Send warning notification email if user has not disabled them by user preference
                    renewal_preference, error_msg = self.get_user_preference('sendRenewalEmails', username)
                    # Send renewal emails by default, but do not send them if the user preference specifically disables it 
                    if renewal_preference != False:
                        # logger.info('Sending warning notification email about pruning files from job "{}"'.format(job_id))
                        given_name, family_name, email = USER_DB_MANAGER.get_basic_info(username)
                        try:
                            email_utils.send_job_prune_warning(
                                username, 
                                [email], 
                                job_name, 
                                job_id, 
                                round(job_warning_period/(24*60*60)), 
                                round(job_ttl/(24*60*60)), 
                                renewals_left, 
                                renewal_token,
                                expiration_date,
                            )
                        except:
                            status = STATUS_ERROR
                            msg = 'Error sending email notification of impending file purge for job "{}" during periodic pruning.'.format(job_id)
        except Exception as e:
            msg = str(e).strip()
            logger.error(msg)
        self.close_db_connection()
        return status, msg

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

        # Validate message option
        if not isinstance(message, str) or message not in ['all', 'new']:
            error_msg = 'message must be string "all" or "new"'
            return messages, error_msg
        
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

            # If the requester is an admin, provide notifications for all roles
            sql_query_admin = '''
                SELECT t1.id, t1.date, t1.title, t1.body
                FROM `message` t1
                INNER JOIN `message_role` t2
                ON t1.id = t2.message_id
            '''
            # Get message IDs visible to each of the user's roles
            sql_query_other = '''
                SELECT t1.id, t1.date, t1.title, t1.body
                FROM `message` t1
                INNER JOIN `message_role` t2
                ON t2.role_name IN {} AND t1.id = t2.message_id
            '''.format(roles_sql)

            if 'admin' in roles:
                sql_query = sql_query_admin
            else:
                sql_query = sql_query_other
            self.cur.execute(sql_query)

            messages_without_roles = []
            if message == 'all':
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
            preferences = {}
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

    def set_user_preference(self, pref, value, username):
        preferences = {}
        error_msg = ''
        if pref == 'all' and not isinstance(value, dict):
            error_msg = 'When setting all preferences, the value must be an object.'
            return error_msg
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
            # If all the preferences are being overwritten use the value directly, otherwise set an individual key-value pair
            if pref == 'all':
                preferences = value
            else:
                preferences[pref] = value
            # If no user preferences have been set yet, create the table record
            if rowId == None:
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
            # Otherwise user preferences exist, so they must be updated.
            else:
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

    def get_statistics_analytics(self):
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "select distinct request_path,count(*) from `analytics` group by request_path" 
                )
            )
            summary = self.cur.fetchall()
            error_msg = ""

        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
            
        self.close_db_connection()
        return summary, error_msg

    def get_statistics_session(self):
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "select count(distinct username) from `session`" 
                )
            )
            summary = self.cur.fetchone()[0]
            error_msg = ""

        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
            
        self.close_db_connection()
        return summary, error_msg

    def get_statistics_cutout(self):
        self.open_db_connection()
        try:
            self.cur.execute(
                (
                    "select file_size from `cutout`" 
                )
            )
        
            summary = sum([float(size) for (size,) in self.cur.fetchall() if size])
            error_msg = ""

        except Exception as e:
            summary = ""
            error_msg = str(e).strip()
            logger.error(error_msg)
            
        self.close_db_connection()
        return summary, error_msg
            
    def get_statistics_query(self):
        self.open_db_connection()
        try:
            self.cur.execute(
               (
                    "select sizes from `query`" 
               )
            )
            totals = []
            for (sizes,) in self.cur:
                size = reformat_query_size(sizes)
                totals.append(size)
            error_msg = ""

        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
            
        self.close_db_connection()
        return sum(totals), error_msg

def reformat_query_size(string):
    bad_chars = ['[',']','"']

    for i in bad_chars:
        string = string.replace(i,'')

    if string:
        string_split = string.split(' ')
        string = string_split[0]
        unit = string_split[1]
    else:
        string = 0
        unit = ''

    if 'KB' in unit:
        string = float(string) * 1000
    if 'MB' in unit:
        string = float(string) * 1e6
    if 'GB' in unit:
        string = float(string) * 1e9

    return float(string)

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


def generate_uuid():
    return str(uuid.uuid4()).replace("-", "")


def get_job_name(jobType, jobId, username):
    return "{}-{}-{}".format(jobType, jobId, username)


def get_job_configmap_name(jobType, jobId, username):
    # Some user names have underscores which are not valid Kubernetes resource name characters
    return "{}-{}-{}-cm".format(jobType, jobId, re.sub(r'_', '', username))


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
        "des_tasks",
        job_type,
        'worker',
        "jobconfig_spec.tpl.yaml"
    )
    with open(jobConfigTemplateFile) as f:
        templateText = f.read()
    return Template(templateText)


def submit_job(params):
    status = STATUS_OK
    msg = ''
    try:
        # Common configurations to all tasks types:
        username = params["username"].lower()
        password = JOBSDB.get_password(username)
        job_id = generate_uuid()
        job_type = params["job"]
        if job_type not in ['test', 'query', 'cutout']:
            status = STATUS_ERROR
            msg = 'Job type "{}" is not valid'.format(job_type)
            return status,msg,job_id
        conf = {}
        conf["job"] = job_type
        conf["db"] = params['db']
        conf["namespace"] = get_namespace()
        conf["cm_name"] = get_job_configmap_name(job_type, job_id, username)
        conf["host_network"] = envvars.HOST_NETWORK        
        # Limit how long a Kubernetes Job can run before being forcibly terminated
        conf['activeDeadlineSeconds'] = 60*60*envvars.LIMIT_MAX_JOB_DURATION_HOURS
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

    # if job_type == 'utility':
    #     try:
    #         logFilePath = "./output/{}_{}_{}.log".format(job_type, params['action'], params['job-id'])
    #     except:
    #         status = STATUS_ERROR
    #         msg = 'Invalid options for utility job type'
    #         return status,msg,''
    # else:
    #     logFilePath = "./output/{}/{}.log".format(conf["job"], job_id)
    logFilePath = "./output/{}/{}.log".format(conf["job"], job_id)

    # Render the base YAML template for the job configuration data structure
    conf['configjob'] = yaml.safe_load(base_template.render(
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
    conf['configjob']['spec'] = {}

    # TODO: Variate the resource requests/limits between the task types
    conf["resource_limit_cpu"] = 1
    conf["resource_request_cpu"] = 1


    # Should the job be executed synchronously or in an independent container (Kubernetes Job)
    # Currently only the cutout job type can be run synchronously
    synchronous_job = job_type == 'cutout' and 'synchronous' in params and str(params['synchronous']).lower() == 'true'

    # Set the output directories
    if synchronous_job:
        logger.info('Synchronous job selected.')
        # When run synchronously, the specific user directory must be explicitly defined
        user_dir = os.path.join('/jobfiles', username)
    else:
        # When run as a k8s Job, the specific user directory is mounted via the Pod spec configuration
        user_dir = '/home/worker/output'
    # Output files 
    outdir = os.path.join(user_dir, 'cutout', job_id)

    # Custom configurations depending on the task type:

    ############################################################################
    # task type: test
    ############################################################################
    if job_type == 'test':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_TEST
        conf["command"] = ["python", "task.py"]
        conf['configjob']['spec'] = yaml.safe_load(template.render(
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
            queryString = params["query"].encode('utf-8').decode('unicode-escape')
            conf['configjob']['spec'] = yaml.safe_load(template.render(
                queryString='',
                fileName=params["filename"],
                quickQuery=quickQuery,
                checkQuery=checkQuery,
                compression=compression
            ))
            # TODO: This is a hack to get around some problem rendering the inputs template when the query
            # has newlines.
            conf['configjob']['spec']['inputs']['queryString'] = queryString
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

        # Set basic user and job info
        spec = {}
        spec['jobid'] = job_id
        spec['username'] = username
        spec['password'] = password
        spec['outdir'] = outdir

        # TODO: Remove these unnecessary parameters from the `cutout` table
        # spec['return_list'] = params['return_list']
        # spec['ra'] = 0.0
        # spec['dec'] = 0.0
        # spec['coadd'] = ''
        # spec['rgb_minimum'] = 0.0
        # spec['rgb_stretch'] = 0.0
        # spec['rgb_asinh'] = 0.0

        # Add all user-defined default values to the user-defined defaults
        cutout_config_string_params = [
            'db',
            'release',
            'colors_fits',
            'rgb_stiff_colors',
            'rgb_lupton_colors',
        ]
        cutout_config_numeric_params = [
            'xsize',
            'ysize',
            'rgb_minimum',
            'rgb_stretch',
            'rgb_asinh',
        ]
        cutout_config_bool_params = [
            'make_fits',
            'make_rgb_lupton',
            'make_rgb_stiff',
            'discard_fits_files',
        ]
        for param in cutout_config_string_params:
            if param in params:
                spec[param] = params[param]
        for param in cutout_config_numeric_params:
            if param in params:
                spec[param] = float(params[param])
        for param in cutout_config_bool_params:
            if param in params:
                spec[param] = str(params[param]).lower() == 'true'
        valid, msg = validate_cutout_user_defaults(spec)
        if not valid:
            status = STATUS_ERROR
            return status,msg,job_id

        # # TODO: Revise the structure of the `cutout` table to reflect
        # # the new input data structure. In the meantime, record both
        # # Lupton and STIFF color set information
        # colors_rgb = ''
        # if 'rgb_stiff_colors' in spec:
        #     colors_rgb += 'rgb_stiff_colors:' + spec['rgb_stiff_colors']
        # if 'rgb_lupton_colors' in spec:
        #     colors_rgb += 'rgb_lupton_colors:' + spec['rgb_lupton_colors']
        # spec['rgb_stiff_colors'] = params['rgb_stiff_colors']
        # spec['rgb_lupton_colors'] = params['rgb_lupton_colors']
        # spec['colors_fits'] = params['colors_fits']

        # RA/DEC and COADD IDs are now ignored. The position information must be included in the
        # CSV-formatted "positions" parameter value.
        if "positions" in params and isinstance(params["positions"], str):
            spec['positions'] = params["positions"].encode('utf-8').decode('unicode-escape')
            valid, msg = validate_cutout_positions_table(spec['positions'])
            if not valid:
                status = STATUS_ERROR
                return status,msg,job_id
        else:
            status = STATUS_ERROR
            msg = 'Cutout job requires at least one cutout request in a CSV-formatted table.'
            return status,msg,job_id

        # Provide the Oracle database service account information
        if spec['db'].upper() == 'DESDR':
            spec['oracle_service_account_db'] = envvars.SERVICE_ACCOUNT_DB
            spec['oracle_service_account_user'] = envvars.SERVICE_ACCOUNT_USER
            spec['oracle_service_account_pass'] = envvars.SERVICE_ACCOUNT_PASS
        else:
            spec['oracle_service_account_db']   = ''
            spec['oracle_service_account_user'] = ''
            spec['oracle_service_account_pass'] = ''

        # Complete the job configuration by defining the `spec` node
        conf['configjob']['spec'] = spec

        # Count the number of positions in the requested job.
        # logger.info('\n{}'.format(spec['positions']))
        num_cutouts = spec['positions'].count('\n')
        if params['limits']['cutout']['cutouts_per_job'] > 0 and num_cutouts > params['limits']['cutout']['cutouts_per_job']:
            status = STATUS_ERROR
            msg = 'Number of requested cutouts ({}) exceeds the maximum allowed per job request ({}).'.format(num_cutouts, params['limits']['cutout']['cutouts_per_job'])
            return status,msg,job_id
        spec['num_cpus'] = 1
        # TODO: Determine the number of CPUs to use in parallel to minimize job execution time
        # if num_cutouts > 1000:
        #     spec['num_cpus'] = 4
        # elif num_cutouts > 100:
        #     spec['num_cpus'] = 3
        # elif num_cutouts > 10:
        #     spec['num_cpus'] = 2

        # Count the number of jobs currently pending for the submitting user.
        if not synchronous_job and params['limits']['cutout']['concurrent_jobs'] > 0:
            num_pending_jobs = JOBSDB.count_pending_jobs(username)
            if num_pending_jobs > params['limits']['cutout']['concurrent_jobs']:
                status = STATUS_ERROR
                msg = 'Number of requested jobs ({}) exceeds the maximum allowed concurrent jobs ({}).'.format(num_pending_jobs, params['limits']['cutout']['concurrent_jobs'])
                return status,msg,job_id

    try:
        # If this is a synchronous run, do not create a Kubernetes Job
        if synchronous_job:
            logger.info('Running synchronously via JobHandler')
            # Register the job in the database
            JOBSDB.register_job(conf)

            # Transcribe the task.py script to run here because the self-HTTP-requests to API endpoints for starting 
            # and stopping the job cannot complete synchronously.
            #
            # Instead of taking the config data and (1) converting to a ConfigMap definition, which is then (2) mounted as
            # a file in the task Job container, which is then (3) imported as a Python dict object, we pass it here directly.
            config = conf['configjob']
            # Make the cutout subdirectory if it does not already exist.
            cutout_dir = os.path.join(user_dir, 'cutout')
            os.makedirs(cutout_dir, exist_ok=True)
            config['cutout_dir'] = cutout_dir
            os.makedirs(config['spec']['outdir'], exist_ok=True)
            # Record task has begun
            JOBSDB.update_job_start(config['metadata']['apiToken'])
            #
            # Execute task
            #
            response = {
                'status': STATUS_OK,
                'msg': ''
            }
            # Dump cutout config to YAML file in working directory
            cutout_config_file = 'cutout_config.yaml'
            with open(cutout_config_file, 'w') as file:
                yaml.dump(config['spec'], file)

            import subprocess
            num_cpus = config['spec']['num_cpus'] if 'num_cpus' in config['spec'] and isinstance(config['spec']['num_cpus'], int) else 1
            args = 'mpirun -n {} python3 des_tasks/cutout/worker/bulkthumbs.py --config {}'.format(num_cpus, cutout_config_file)
            try:
                run_output = subprocess.check_output([args], shell=True)
            except subprocess.CalledProcessError as e:
                logging.error(e.output)
                response['status'] = STATUS_ERROR
                response['msg'] = e.output
            #
            # Task complete
            #
            import glob
            # Report that work has completed
            # If no errors have occurred already, parse the job summary file for file info
            path = config['spec']['outdir']
            files = glob.glob(os.path.join(path, '*/*/*'))
            relpaths = []
            total_size = 0.0
            for file in files:
                relpaths.append(os.path.relpath(file, start=config['cutout_dir']))
                total_size += os.path.getsize(file)
            response['files'] = relpaths
            response['sizes'] = total_size
            # Hack to avoid kubejob.delete in job completion
            response['synchronous'] = True
            JOBSDB.update_job_complete(config['metadata']['apiToken'], response)
        else:
            kubejob.create_configmap(conf)
            kubejob_status, kubejob_msg = kubejob.create_job(conf)
            if kubejob_status == STATUS_ERROR:
                status = STATUS_ERROR
                msg = kubejob_msg
                return status,msg,job_id
            # Register the job in the database
            JOBSDB.register_job(conf)
    except Exception as e:
        status = STATUS_ERROR
        msg = str(e).strip()
        logger.error(msg)
        return status,msg,job_id
    msg = "Job:{} id:{} by:{}".format(job_type, job_id, username)
    return status,msg,job_id


