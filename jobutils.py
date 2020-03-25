import os
import uuid
from jinja2 import Template
import secrets
import kubejob
import yaml
from jobsdb import JobsDb
import envvars

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
        "jobconfig.tpl.yaml"
    )
    with open(jobConfigTemplateFile) as f:
        templateText = f.read()
    return Template(templateText)

def submit_job(params):
    # Common configurations to all tasks types:
    username = params["username"].lower()
    job_type = params["job"]
    job_id = generate_job_id()
    conf = {}
    conf["job"] = job_type
    conf["namespace"] = get_namespace()
    conf["cm_name"] = get_job_configmap_name(conf["job"], job_id, username)
    conf["job_name"] = get_job_name(conf["job"], job_id, username)
    conf["host_network"] = envvars.HOST_NETWORK
    conf["command"] = ["python", "task.py"]
    template = get_job_template(job_type)
    base_template = get_job_template_base()
    # Render the base YAML template for the job configuration data structure
    conf["configjob"] = yaml.safe_load(base_template.render(
        taskType=conf["job"],
        jobName=conf["job_name"],
        jobId=job_id,
        username=username,
        logFilePath="./output/{}.log".format(conf["job_name"]),
        apiToken=secrets.token_hex(16),
        apiBaseUrl=envvars.API_BASE_URL,
        persistentVolumeClaim='{}{}'.format(envvars.PVC_NAME_BASE, conf["job"]),
        debug=False
    ))
    conf["configjob"]["spec"] = {}

    # Custom configurations depending on the task type:
    if job_type == 'test':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_TEST
        conf["configjob"]["spec"] = yaml.safe_load(template.render(
            taskDuration=int(params["time"])
        ))
    elif job_type == 'query':
        conf["image"] = envvars.DOCKER_IMAGE_TASK_QUERY
        conf["configjob"]["spec"] = yaml.safe_load(template.render(
            queryString=params["query"],
            dbPassword=''
        ))
    else:
        # Invalid job type
        job_id=''

    if job_id == '':
        msg = 'Job type "{}" is not defined'.format(job_type)
    else:
        msg = "Job:{} id:{} by:{}".format(job_type, job_id, username)

    kubejob.create_configmap(conf)
    kubejob.create_job(conf)
    status = "ok"
    JOBSDB.register_job(conf)
    return status,msg,job_id
