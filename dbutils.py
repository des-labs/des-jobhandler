import cx_Oracle
from tenacity import retry
import tenacity
import logging
import envvars
import yaml
import os
import datetime as dt
import uuid


STATUS_OK = 'ok'
STATUS_ERROR = 'error'

logger = logging.getLogger(__name__)

class dbConfig(object):
    def __init__(self, manager_db):
        file = os.path.join(
            os.path.dirname(__file__),
            "oracle_user_manager.yaml"
        )
        with open(file, 'r') as cfile:
            conf = yaml.load(cfile)[manager_db]
        self.host = conf['host']
        self.port = conf['port']
        self.user_manager = conf['user']
        self.pwd_manager = conf['passwd']
        self.admin_user_manager = conf['admin_user']
        self.admin_pwd_manager = conf['admin_passwd']
        self.db_manager = manager_db

    @retry(reraise=True, stop=tenacity.stop.stop_after_attempt(2), wait=tenacity.wait.wait_fixed(2))
    def __login(self, user, passwd, dsn):
        logger.info('Connecting to DB as {}...'.format(user))
        try:
            dbh = cx_Oracle.connect(user, passwd, dsn=dsn)
            dbh.close()
            return True, "", False
        except Exception as e:
            raise e

    def check_credentials(self, username, password, db):
        kwargs = {'host': self.host, 'port': self.port, 'service_name': db}
        dsn = cx_Oracle.makedsn(**kwargs)
        update = False
        try:
            auth, error, update = self.__login(username, password, dsn)
            return auth, error, update
        except Exception as e:
            error = str(e).strip()
            if '28001' in error:
                update = True
            return False, error, update

    def get_basic_info(self, user):
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.user_manager, self.pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            cc = cursor.execute("select firstname,lastname,email from DES_ADMIN.DES_USERS where "
                                "upper(username) = '{}'".format(user.upper())).fetchone()
        except:
            cc = ('','','')
        cursor.close()
        dbh.close()
        return cc

    def list_all_users(self):
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.user_manager, self.pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            cc = cursor.execute("select username,firstname,lastname,email from DES_ADMIN.DES_USERS").fetchall()
        except:
            cc = ('','','','')
        cursor.close()
        dbh.close()
        return cc

    def update_info(self, username, firstname, lastname, email):
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.user_manager, self.pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        qupdate = """
            UPDATE  DES_ADMIN.DES_USERS SET
            FIRSTNAME = '{first}',
            LASTNAME = '{last}',
            EMAIL = '{email}'
            WHERE USERNAME = '{user}'
            """.format(first=firstname, last=lastname, email=email, user=username.lower())
        try:
            cursor.execute(qupdate)
            dbh.commit()
            msg = 'Information for {} Updated'.format(username)
            status = 'ok'
        except Exception as e:
            msg = str(e).strip()
            status = 'error'
        cursor.close()
        dbh.close()
        return status, msg

    def change_credentials(self, username, oldpwd, newpwd, db):
        auth, error, update = self.check_credentials(username, oldpwd, db)
        kwargs = {'host': self.host, 'port': self.port, 'service_name': db}
        dsn = cx_Oracle.makedsn(**kwargs)
        if auth:
            try:
                dbh = cx_Oracle.connect(username, oldpwd, dsn=dsn, newpassword=newpwd)
                dbh.close()
                return 'ok', "Password changed"
            except Exception as e:
                error = str(e).strip()
                return 'error', error
        if update:
            try:
                dbh = cx_Oracle.connect(username, oldpwd, dsn=dsn, newpassword=newpwd)
                dbh.close()
                return 'ok', "Password that expired was changed"
            except Exception as e:
                error = str(e).strip()
                return 'error', error
        else:
            return 'error', error
    
    def check_username(self, username):
        status = STATUS_OK
        msg = ''
        results = None
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.user_manager, self.pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        sql = """
            SELECT USERNAME FROM DES_ADMIN.DES_USERS WHERE USERNAME = '{user}'
            """.format(user=username.lower())
        try:
            results = cursor.execute(sql).fetchone()
            if results:
                status = STATUS_ERROR
                msg = 'Username {} is unavailable. Choose a different one.'.format(username)
        except Exception as e:
            msg = str(e).strip()
            status = STATUS_ERROR
        cursor.close()
        dbh.close()
        return status, msg

    def update_password(self, username, password):
        status = STATUS_OK
        msg = ''
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            sql = """
            ALTER USER {0} IDENTIFIED BY {1}
            """.format(username.lower(), password)
            #logger.info('sql: {}'.format(sql))
            valid = False
            try:
                cursor.execute(sql)
                dbh.commit()
                valid = True
            except Exception as e:
                msg = str(e).strip()
            if valid:
                # Delete the reset token
                sql = """
                DELETE FROM DES_ADMIN.RESET_URL WHERE USERNAME = '{}'
                """.format(username.lower())
                #logger.info('sql: {}'.format(sql))
                cursor.execute(sql)
                dbh.commit()
        except Exception as e:
            status = STATUS_ERROR
            msg = str(e).strip()
            logger.error(msg)
        cursor.close()
        dbh.close()
        return status, msg

    def unlock_account(self, username):
        status = STATUS_OK
        msg = ''
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            sql = """
            ALTER USER {} ACCOUNT UNLOCK
            """.format(username.lower())
            #logger.info('sql: {}'.format(sql))
            cursor.execute(sql)
            dbh.commit()
            # Delete the reset token
            sql = """
            DELETE FROM DES_ADMIN.RESET_URL WHERE USERNAME = '{}'
            """.format(username.lower())
            #logger.info('sql: {}'.format(sql))
            cursor.execute(sql)
            dbh.commit()
        except Exception as e:
            status = STATUS_ERROR
            msg = str(e).strip()
            logger.error(msg)
        cursor.close()
        dbh.close()
        return status, msg

    def validate_token(self, token, timeout=6000):
        valid = False
        status = STATUS_OK
        msg = ''
        results = None
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        sql = """
            SELECT CREATED, USERNAME FROM DES_ADMIN.RESET_URL WHERE URL = '{0}'
            """.format(token)
        #logger.info('sql: {}'.format(sql))
        try:
            created, username = None, None
            for row in cursor.execute(sql):
                #logger.info('{}'.format(row))
                created, username = row
                if not created:
                    msg = 'Activation token is invalid'
                    logger.info(msg)
                else:
                    if (dt.datetime.now() - created).seconds > timeout:
                        msg = 'Activation token has expired'
                        logger.info(msg)
                    else:
                        valid = True
        except Exception as e:
            logger.error('Error selecting reset URL')
            valid = False
            msg = str(e).strip()
            status = STATUS_ERROR
        cursor.close()
        dbh.close()
        return valid, username, status, msg

    def check_email(self, email):
        status = STATUS_OK
        msg = ''
        results = None
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.user_manager, self.pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        sql = """
            SELECT EMAIL FROM DES_ADMIN.DES_USERS WHERE EMAIL = '{}'
            """.format(email.lower())
        try:
            results = cursor.execute(sql).fetchone()
            if results:
                status = STATUS_ERROR
                msg = 'Email address {} is already registered.'.format(email)
        except Exception as e:
            msg = str(e).strip()
            status = STATUS_ERROR
        cursor.close()
        dbh.close()
        return status, msg

    def create_reset_url(self, username):
        url = None
        firstname = None
        lastname = None
        status = STATUS_OK
        msg = ''
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        # The admin credentials are required for the delete and insert commands
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            # Get user profile
            sql = """
            SELECT EMAIL, FIRSTNAME, LASTNAME from DES_ADMIN.DES_USERS where USERNAME = '{}'
            """.format(username.lower())
            #logger.info('sql: {}'.format(sql))
            results = cursor.execute(sql).fetchone()
            if not results:
                status = STATUS_ERROR
                msg = 'user {} not registered.'.format(username)
            else:
                email, firstname, lastname = results
                #logger.info('{},{},{}'.format(username, firstname, lastname))
                # Delete any existing reset codes
                sql = """
                DELETE FROM DES_ADMIN.RESET_URL WHERE USERNAME = '{user}'
                """.format(user=username)
                #logger.info('sql: {}'.format(sql))
                cursor.execute(sql)
                dbh.commit()
                now = dt.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                url = uuid.uuid4().hex
                sql = """
                INSERT INTO DES_ADMIN.RESET_URL VALUES ('{0}', '{1}', to_date('{2}' , 'yyyy/mm/dd hh24:mi:ss'))
                """.format(username, url, now)
                #logger.info('sql: {}'.format(sql))
                cursor.execute(sql)
                dbh.commit()
        except Exception as e:
            url = None
            firstname = None
            lastname = None
            msg = str(e).strip()
            status = STATUS_ERROR
        cursor.close()
        dbh.close()
        return url, firstname, lastname, email, status, msg

    def delete_user(self, username):
        status = STATUS_OK
        msg = ''
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        # The admin credentials are required for the DELETE and DROP commands
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            sql = """
            DELETE FROM DES_ADMIN.RESET_URL WHERE USERNAME = '{user}'
            """.format(user=username.lower())
            #logger.info('sql: {}'.format(sql))
            results = cursor.execute(sql)
            #logger.info('cursor.execute results: {}'.format(results))
            
            sql = """
            DELETE FROM DES_ADMIN.DES_USERS where USERNAME = '{user}'
            """.format(user=username.lower())
            #logger.info('sql: {}'.format(sql))
            results = cursor.execute(sql)
            #logger.info('cursor.execute results: {}'.format(results))
            
            sql = """
            DROP USER {user} CASCADE
            """.format(user=username.lower())
            #logger.info('sql: {}'.format(sql))
            results = cursor.execute(sql)
            #logger.info('cursor.execute results: {}'.format(results))
            
        except Exception as e:
            msg = str(e).strip()
            status = STATUS_ERROR
        cursor.close()
        dbh.close()
        return status, msg

    def create_user(self, username, password, first, last, email, country = '', institution = '', lock=True):
        status = STATUS_OK
        msg = ''
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        # The admin credentials are required for the CREATE, GRANT, and INSERT commands
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            sql = """
            CREATE USER {user} IDENTIFIED BY {passwd} DEFAULT TABLESPACE USERS
            """.format(user=username.lower(), passwd=password)
            if lock:
                sql = '{} ACCOUNT LOCK'.format(sql)
            #logger.info('create user sql: {}'.format(sql))
            results = cursor.execute(sql)
            #logger.info('cursor.execute results: {}'.format(results))
            
            sql = """
            GRANT CREATE SESSION to {user}
            """.format(user=username.lower())
            #logger.info('grant session sql: {}'.format(sql))
            results = cursor.execute(sql)
            #logger.info('cursor.execute results: {}'.format(results))

            tables = ['DES_ADMIN.CACHE_TABLES', 'DES_ADMIN.CACHE_COLUMNS']
            for itable in tables:
                sql = """
                GRANT SELECT on {table} to {user}
                """.format(table=itable, user=username.lower())
                #logger.info('grant select on table sql: {}'.format(sql))
                results = cursor.execute(sql)
                #logger.info('cursor.execute results: {}'.format(results))

            sql = """
            INSERT INTO DES_ADMIN.DES_USERS VALUES (
            '{user}', '{first}', '{last}', '{email}', '{country}', '{inst}'
            )
            """.format(
                user=username.lower(),
                first=first,
                last=last,
                email=email,
                country=country,
                inst=institution
            )
            #logger.info('insert user into DES_USERS sql: {}'.format(sql))
            results = cursor.execute(sql)
            #logger.info('cursor.execute results: {}'.format(results))
            
            sql = """
            GRANT DES_READER to {user}
            """.format(user=username.lower())
            #logger.info('GRANT DES_READER sql: {}'.format(sql))
            results = cursor.execute(sql)
            #logger.info('cursor.execute results: {}'.format(results))

        except Exception as e:
            msg = str(e).strip()
            status = STATUS_ERROR
        cursor.close()
        dbh.close()
        return status, msg


