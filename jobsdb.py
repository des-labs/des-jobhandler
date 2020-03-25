import mysql.connector
import os
import json
import datetime
import kubejob
import jobutils

class JobsDb:
    def __init__(self, mysql_host, mysql_user, mysql_password, mysql_database):
        self.host = mysql_host
        self.user = mysql_user
        self.password = mysql_password
        self.database = mysql_database
        self.cur = None
        self.cnx = None

    def open_db_connection(self):
        if self.cnx != None and self.cur != None:
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
            'user',
            'group',
            'group_membership',
            'session'
        ]

    def reinitialize_tables(self):
        self.open_db_connection()
        for table in self.get_table_names():
            self.cur.execute("DROP TABLE IF EXISTS {}".format(table))
        # Create the database tables
        with open(os.path.join(os.path.dirname(__file__), "db_schema.sql")) as f:
            dbSchema = f.read()
        self.cur.execute(dbSchema)
        self.close_db_connection()

    def validate_apitoken(self, apitoken):
        self.open_db_connection()
        self.cur.execute(
            "SELECT id FROM Jobs WHERE apitoken = '{}' LIMIT 1".format(
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
        self.cur.execute(newJobSql, newJobInfo)
        self.close_db_connection()

    def update_job_start(self, rowId):
        self.open_db_connection()
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
        self.cur.execute(updateJobSql, updateJobInfo)
        error_msg = None
        if self.cur.rowcount != 1:
            error_msg = 'Error updating job record'
        self.close_db_connection()
        return error_msg

    def update_job_complete(self, rowId):
        self.open_db_connection()
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
        self.cur.execute(updateJobSql, updateJobInfo)
        error_msg = None
        if self.cur.rowcount != 1:
            error_msg = 'Error updating job record {}'.format(rowId)
        else:
            selectJobSql = (
                "SELECT user,job,name from Jobs WHERE id=%s"
            )
            selectJobInfo = (
                rowId,
            )
            self.cur.execute(selectJobSql, selectJobInfo)
            for (user, job, name) in self.cur:
                conf = {"job": job}
                conf['namespace'] = jobutils.get_namespace()
                conf["job_name"] = jobutils.get_job_name(conf["job"], name, user)
                conf["cm_name"] = jobutils.get_job_configmap_name(
                    conf["job"], name, user)
                kubejob.delete_job(conf)
        self.close_db_connection()
        return error_msg
