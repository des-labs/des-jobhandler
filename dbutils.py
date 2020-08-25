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
    def __init__(self, manager_db, all_databases):
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
        self.databases = all_databases

    @retry(reraise=True, stop=tenacity.stop.stop_after_attempt(2), wait=tenacity.wait.wait_fixed(2))
    def __login(self, user, passwd, dsn):
        logger.info('Connecting to DB as {}...'.format(user))
        try:
            dbh = cx_Oracle.connect(user, passwd, dsn=dsn)
            dbh.close()
            return True, "", False
        except Exception as e:
            raise e

    def get_username_from_email(self, email):
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.user_manager, self.pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        username = None
        try:
            sql = """
            SELECT USERNAME, EMAIL from DES_ADMIN.DES_USERS where EMAIL = '{}'
            """.format(email.lower())
            for row in cursor.execute(sql):
                username, email = row
        except Exception as e:
            logger.error(str(e).strip())
        cursor.close()
        dbh.close()
        return username

    def check_credentials(self, username, password, db, email=''):
        kwargs = {'host': self.host, 'port': self.port, 'service_name': db}
        dsn = cx_Oracle.makedsn(**kwargs)
        update = False
        try:
            # Get username from account with registered email address if provided
            if email != '':
                username_from_email = self.get_username_from_email(email)
                if not username_from_email:
                    return False, username, 'email is not registered', update
                else:
                    username = username_from_email
            # If email is not provided, require username parameter
            if not username:
                return False, username, 'Registered username or email is required', update
            auth, error, update = self.__login(username, password, dsn)
            return auth, username, error, update
        except Exception as e:
            error = str(e).strip()
            if '28001' in error:
                update = True
            return False, username, error, update

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
        username = username.lower()
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
            """.format(first=firstname, last=lastname, email=email, user=username)
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
        auth, username, error, update = self.check_credentials(username, oldpwd, db)
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
        username = username.lower()
        results = None
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.user_manager, self.pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        sql = """
            SELECT USERNAME FROM DES_ADMIN.DES_USERS WHERE USERNAME = '{user}'
            """.format(user=username)
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
        username = username.lower()
        for db in self.databases:
            # self.db_manager = db
            # Open an Oracle connection and get a Cursor object
            try:
                kwargs = {'host': self.host, 'port': self.port, 'service_name': db}
                dsn = cx_Oracle.makedsn(**kwargs)
                dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
                logger.info('connecting to {} with user: {}'.format(db, self.admin_user_manager))
                cursor = dbh.cursor()
                
                # Unlock account in case it is locked for some reason
                status, msg = self.unlock_account(username, db)
                if status != STATUS_OK:
                    status = STATUS_ERROR
                    logger.error(msg)
                    cursor.close()
                    dbh.close()
                    return status, msg

                # If on the public interface, use a different SQL command than in the private interface
                if envvars.DESACCESS_INTERFACE == 'public':
                    sql = """
                    ALTER USER {0} IDENTIFIED BY {1}
                    """.format(username, password)
                    cursor.execute(sql)
                    dbh.commit()
                else:
                    logger.info('Executing RESET_PASSWORD ({},****)...'.format(username))
                    result = cursor.callproc('RESET_PASSWORD', [username, password])
                    # logger.info('Result RESET_PASSWORD: {}'.format(result))
                # If the procedure calls do not throw an error, assume success
                # Delete the reset token
                logger.info('Deleting reset token "{}"...'.format(username))
                status, msg = self.clear_reset_token(username)
                cursor.close()
                dbh.close()
            except Exception as e:
                status = STATUS_ERROR
                msg = str(e).strip()
                logger.error(msg)
                cursor.close()
                dbh.close()
                break
        return status, msg

    def clear_reset_token(self, username):
        status = STATUS_OK
        msg = ''
        username = username.lower()
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            # Delete the reset token
            sql = """
            DELETE FROM DES_ADMIN.RESET_URL WHERE USERNAME = '{}'
            """.format(username)
            cursor.execute(sql)
            dbh.commit()
        except Exception as e:
            status = STATUS_ERROR
            msg = str(e).strip()
            logger.error(msg)
        cursor.close()
        dbh.close()
        return status, msg

    def unlock_account(self, username, db=''):
        status = STATUS_OK
        msg = ''
        username = username.lower()
        if not db:
            db = self.db_manager
        kwargs = {'host': self.host, 'port': self.port, 'service_name': db}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            if envvars.DESACCESS_INTERFACE == 'public':
                sql = """
                ALTER USER {} ACCOUNT UNLOCK
                """.format(username)
                cursor.execute(sql)
                dbh.commit()
            else:
                logger.info('Executing UNLOCKUSER...')
                result = cursor.callproc('UNLOCKUSER', [username])
                logger.info('Result UNLOCKUSER: {}'.format(result))
            # Delete the reset token
            status, msg = self.clear_reset_token(username)
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
        msg = 'Activation token is invalid'
        results = None
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        sql = """
            SELECT CREATED, USERNAME FROM DES_ADMIN.RESET_URL WHERE URL = '{0}'
            """.format(token)
        try:
            created, username = None, None
            for row in cursor.execute(sql):
                created, username = row
                if not created:
                    msg = 'Activation token is invalid'
                    logger.info(msg)
                else:
                    if (dt.datetime.now() - created).seconds > timeout:
                        msg = 'Activation token has expired'
                        logger.info(msg)
                    else:
                        msg = ''
                        valid = True
        except Exception as e:
            logger.error('Error selecting reset URL')
            valid = False
            # msg = str(e).strip()
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

    def create_reset_url(self, username, email=''):
        url = None
        firstname = None
        lastname = None
        status = STATUS_OK
        msg = ''
        username = username.lower()
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        # The admin credentials are required for the delete and insert commands
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            if email:
                username_or_email = 'EMAIL'
                identifier = email
            else:
                username_or_email = 'USERNAME'
                identifier = username
            # Get user profile
            sql = """
            SELECT USERNAME, EMAIL, FIRSTNAME, LASTNAME from DES_ADMIN.DES_USERS where {} = '{}'
            """.format(username_or_email, identifier)
            results = cursor.execute(sql).fetchone()
            if not results:
                status = STATUS_ERROR
                msg = 'user or email not registered.'
            else:
                username, email, firstname, lastname = results
                # Delete any existing reset codes
                status, msg = self.clear_reset_token(username)

                now = dt.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                url = uuid.uuid4().hex
                sql = """
                INSERT INTO DES_ADMIN.RESET_URL VALUES ('{0}', '{1}', to_date('{2}' , 'yyyy/mm/dd hh24:mi:ss'))
                """.format(username, url, now)
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
        return url, firstname, lastname, email, username, status, msg

    def delete_user(self, username):
        status = STATUS_OK
        msg = ''
        username = username.lower()
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        # The admin credentials are required for the DELETE and DROP commands
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            status, msg = self.clear_reset_token(username)
            
            sql = """
            DELETE FROM DES_ADMIN.DES_USERS where USERNAME = '{user}'
            """.format(user=username)
            results = cursor.execute(sql)
            
            sql = """
            DROP USER {user} CASCADE
            """.format(user=username)
            results = cursor.execute(sql)
            
        except Exception as e:
            msg = str(e).strip()
            status = STATUS_ERROR
        cursor.close()
        dbh.close()
        return status, msg

    def create_user(self, username, password, first, last, email, country = '', institution = '', lock=True):
        status = STATUS_OK
        msg = ''
        username = username.lower()
        kwargs = {'host': self.host, 'port': self.port, 'service_name': self.db_manager}
        dsn = cx_Oracle.makedsn(**kwargs)
        # The admin credentials are required for the CREATE, GRANT, and INSERT commands
        dbh = cx_Oracle.connect(self.admin_user_manager, self.admin_pwd_manager, dsn=dsn)
        cursor = dbh.cursor()
        try:
            sql = """
            CREATE USER {user} IDENTIFIED BY {passwd} DEFAULT TABLESPACE USERS
            """.format(user=username, passwd=password)
            if lock:
                sql = '{} ACCOUNT LOCK'.format(sql)
            results = cursor.execute(sql)
            
            sql = """
            GRANT CREATE SESSION to {user}
            """.format(user=username)
            results = cursor.execute(sql)

            tables = ['DES_ADMIN.CACHE_TABLES', 'DES_ADMIN.CACHE_COLUMNS']
            for itable in tables:
                sql = """
                GRANT SELECT on {table} to {user}
                """.format(table=itable, user=username)
                results = cursor.execute(sql)

            sql = """
            INSERT INTO DES_ADMIN.DES_USERS VALUES (
            '{user}', '{first}', '{last}', '{email}', '{country}', '{inst}'
            )
            """.format(
                user=username,
                first=first,
                last=last,
                email=email,
                country=country,
                inst=institution
            )
            results = cursor.execute(sql)
            
            sql = """
            GRANT DES_READER to {user}
            """.format(user=username)
            results = cursor.execute(sql)

        except Exception as e:
            msg = str(e).strip()
            status = STATUS_ERROR
        cursor.close()
        dbh.close()
        return status, msg


