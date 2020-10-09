import os
import re

# Import and initialize environment variable values
DOCKER_IMAGE_TASK_QUERY = os.environ['DOCKER_IMAGE_TASK_QUERY']
DOCKER_IMAGE_TASK_CUTOUT = os.environ['DOCKER_IMAGE_TASK_CUTOUT']
DOCKER_IMAGE_JLAB_SERVER= os.environ['DOCKER_IMAGE_JLAB_SERVER']
INGRESS_CLASS_JLAB_SERVER= os.environ['INGRESS_CLASS_JLAB_SERVER']
API_BASE_URL = os.environ['API_BASE_URL']
FRONTEND_BASE_URL = os.environ['FRONTEND_BASE_URL'].rstrip('/')
PVC_NAME_BASE = os.environ['PVC_NAME_BASE']
MYSQL_HOST = os.environ['MYSQL_HOST']
MYSQL_DATABASE = os.environ['MYSQL_DATABASE']
MYSQL_USER = os.environ['MYSQL_USER']
MYSQL_PASSWORD = os.environ['MYSQL_PASSWORD']
SERVICE_ACCOUNT_DB   = os.environ['SERVICE_ACCOUNT_DB']
SERVICE_ACCOUNT_USER = os.environ['SERVICE_ACCOUNT_USER']
SERVICE_ACCOUNT_PASS = os.environ['SERVICE_ACCOUNT_PASS']
SERVICE_PORT = os.environ['SERVICE_PORT']
BASE_PATH = os.environ['BASE_PATH']
BASE_DOMAIN = os.environ['BASE_DOMAIN']
TLS_SECRET = os.environ['TLS_SECRET']
JWT_TTL_SECONDS = int(os.environ['JWT_TTL_SECONDS'])
HOST_NETWORK = os.environ['HOST_NETWORK']
JWT_HS256_SECRET = os.environ['JWT_HS256_SECRET']
DROP_TABLES = os.environ['DROP_TABLES'].lower() == 'true'
DEBUG_JOB = os.environ['DEBUG_JOB'].lower() == 'true'
CONFIG_FOLDER_ROOT = os.environ['CONFIG_FOLDER_ROOT']
ORACLE_PUB = os.environ['ORACLE_USER_MANAGER_DB_PUBLIC']
ORACLE_PRV = os.environ['ORACLE_USER_MANAGER_DB_PRIVATE']
ORACLE_PUB_DBS = os.environ['ORACLE_USER_MANAGER_DB_PUBLIC_DBS'].split(',')
ORACLE_PRV_DBS = os.environ['ORACLE_USER_MANAGER_DB_PRIVATE_DBS'].split(',')
DESACCESS_INTERFACE = os.environ['DESACCESS_INTERFACE']
ALLOWED_ROLE_LIST = os.environ['ALLOWED_ROLE_LIST']
DESACCESS_ADMIN_EMAILS = os.environ['DESACCESS_ADMIN_EMAILS'].split(',')
DESACCESS_PUBLIC_EMAILS = os.environ['DESACCESS_PUBLIC_EMAILS'].split(',')
JIRA_DEFAULT_ASSIGNEE = os.environ['JIRA_DEFAULT_ASSIGNEE']
LIMIT_CUTOUTS_CUTOUTS_PER_JOB = int(os.environ['LIMIT_CUTOUTS_CUTOUTS_PER_JOB'])
LIMIT_CUTOUTS_CONCURRENT_JOBS = int(os.environ['LIMIT_CUTOUTS_CONCURRENT_JOBS'])
DESACCESS_JOB_FILES_LIFETIME = int(os.environ['DESACCESS_JOB_FILES_LIFETIME'])
DESACCESS_JOB_FILES_WARNING_PERIOD = int(os.environ['DESACCESS_JOB_FILES_WARNING_PERIOD'])
DESACCESS_JOB_FILES_MAX_RENEWALS = int(os.environ['DESACCESS_JOB_FILES_MAX_RENEWALS'])

FRONTEND_BASE_PATH = re.sub(r'http.*\/\/{}'.format(BASE_DOMAIN), '', FRONTEND_BASE_URL)
