import cx_Oracle
from tenacity import retry
import tenacity
import logging
import envvars
logger = logging.getLogger(__name__)


# TODO: Move to Settings
class dbConfig(object):
    def __init__(self):
        self.host = 'desdb.ncsa.illinois.edu'
        self.port = '1521'
        self.user_manager = envvars.ORACLE_USER_MANAGER
        self.pwd_manager = envvars.ORACLE_PWD_MANAGER
        self.db_manager = 'desoper'

dbConf=dbConfig()

@retry(reraise=True, stop=tenacity.stop.stop_after_attempt(2), wait=tenacity.wait.wait_fixed(2))
def _login(user, passwd, dsn):
    logger.info('Connecting to DB as {}...'.format(user))
    try:
        dbh = cx_Oracle.connect(user, passwd, dsn=dsn)
        dbh.close()
        return True, "", False
    except Exception as e:
        raise e

def check_credentials(username, password, db):
    kwargs = {'host': dbConf.host, 'port': dbConf.port, 'service_name': db}
    dsn = cx_Oracle.makedsn(**kwargs)
    update = False
    try:
        auth, error, update = _login(username, password, dsn)
        return auth, error, update
    except Exception as e:
        error = str(e).strip()
        if '28001' in error:
            update = True
        return False, error, update

def get_basic_info(user):
    kwargs = {'host': dbConf.host, 'port': dbConf.port, 'service_name': dbConf.db_manager}
    dsn = cx_Oracle.makedsn(**kwargs)
    dbh = cx_Oracle.connect(dbConf.user_manager, dbConf.pwd_manager, dsn=dsn)
    cursor = dbh.cursor()
    try:
        cc = cursor.execute("select firstname,lastname,email from des_users where "
                            "upper(username) = '{}'".format(user.upper())).fetchone()
    except:
        cc = ('','','')
    cursor.close()
    dbh.close()
    return cc


def update_info(username, firstname, lastname, email):
    kwargs = {'host': dbConf.host, 'port': dbConf.port, 'service_name': dbConf.db_manager}
    dsn = cx_Oracle.makedsn(**kwargs)
    dbh = cx_Oracle.connect(dbConf.user_manager, dbConf.pwd_manager, dsn=dsn)
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

def change_credentials(username, oldpwd, newpwd, db):
    auth, error, update = check_credentials(username, oldpwd, db)
    kwargs = {'host': dbConf.host, 'port': dbConf.port, 'service_name': db}
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

