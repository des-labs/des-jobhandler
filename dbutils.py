import cx_Oracle
from tenacity import retry
import tenacity
import logging
import envvars
import yaml
import os

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
