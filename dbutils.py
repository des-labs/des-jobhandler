import cx_Oracle
from tenacity import retry
import tenacity
import logging
logger = logging.getLogger(__name__)


# TODO: Move to Settings
class dbConfig(object):
    def __init__(self):
        self.host = 'desdb.ncsa.illinois.edu'
        self.port = '1521'

dbConf=dbConfig()

@retry(reraise=True, stop=tenacity.stop.stop_after_attempt(3), wait=tenacity.wait.wait_fixed(1))
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

def get_basic_info(username, password, user):
    kwargs = {'host': dbConf.host, 'port': dbConf.port, 'service_name': 'desoper'}
    dsn = cx_Oracle.makedsn(**kwargs)
    dbh = cx_Oracle.connect(username, password, dsn=dsn)
    cursor = dbh.cursor()
    try:
        cc = cursor.execute("select firstname,lastname,email from des_users where "
                            "upper(username) = '{}'".format(user.upper())).fetchone()
    except:
        cc = ('','','')
    cursor.close()
    dbh.close()
    return cc