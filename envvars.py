import os

# Import and initialize environment variable values
DOCKER_IMAGE_TASK_TEST = os.environ['DOCKER_IMAGE_TASK_TEST']
DOCKER_IMAGE_TASK_QUERY = os.environ['DOCKER_IMAGE_TASK_QUERY']
API_BASE_URL = os.environ['API_BASE_URL']
PVC_NAME_BASE = os.environ['PVC_NAME_BASE']
MYSQL_HOST = os.environ['MYSQL_HOST']
MYSQL_DATABASE = os.environ['MYSQL_DATABASE']
MYSQL_USER = os.environ['MYSQL_USER']
MYSQL_PASSWORD = os.environ['MYSQL_PASSWORD']
SERVICE_PORT = os.environ['SERVICE_PORT']
BASE_PATH = os.environ['BASE_PATH']
JWT_TTL_SECONDS = int(os.environ['JWT_TTL_SECONDS'])
HOST_NETWORK = os.environ['HOST_NETWORK']
JWT_HS256_SECRET = os.environ['JWT_HS256_SECRET']
DROP_TABLES = os.environ['DROP_TABLES'].lower() == 'true'
CONFIG_FOLDER_ROOT = os.environ['CONFIG_FOLDER_ROOT']
ORACLE_USER_MANAGER = os.environ['ORACLE_USER_MANAGER']
ORACLE_PWD_MANAGER = os.environ['ORACLE_PWD_MANAGER']
