import logging
import yaml
import sys
import os
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from jinja2 import Template
import envvars

STATUS_OK = 'ok'
STATUS_ERROR = 'error'

logger = logging.getLogger(__name__)
try:
    config.load_kube_config(config_file="k8s.conf")
except:
    config.load_incluster_config()
configuration = client.Configuration()
api_batch_v1 = client.BatchV1Api(client.ApiClient(configuration))
api_v1 = client.CoreV1Api(client.ApiClient(configuration))


def test_credentials():
    try:
        api_response = api_v1.get_api_resources()
        logging.info(api_response)
    except ApiException as e:
        print("Exception when calling API: {}\n".format(e))


def job(input):

    with open(os.path.join(os.path.dirname(__file__), "job.tpl.yaml")) as f:
        templateText = f.read()

    imagePullPolicy = 'IfNotPresent'
    try:
        if input["image"].split(':')[1] in ['latest', 'dev']:
            imagePullPolicy = 'Always'
    except:
        pass

    template = Template(templateText)
    body = yaml.safe_load(template.render(
        name=input["configjob"]["metadata"]["jobId"],
        namespace=input["namespace"],
        backoffLimit=2,
        hostNetwork=input["host_network"],
        activeDeadlineSeconds=input['activeDeadlineSeconds'], # No Job is allowed to run beyond 24 hours.
        ttlSecondsAfterFinished=120,
        container_name=input["job"],
        image=input["image"],
        imagePullPolicy=imagePullPolicy,
        command=input["command"],
        configmap_name=input["cm_name"],
        pvc_name=input["configjob"]["metadata"]["persistentVolumeClaim"],
        username=input["configjob"]["metadata"]["username"],
        resource_limit_cpu=input["resource_limit_cpu"],
        resource_request_cpu=input["resource_request_cpu"],
        desarchiveHostPath=envvars.DESARCHIVE_HOST_PATH,
        coaddHostPath=envvars.COADD_HOST_PATH,
        uid=envvars.JOB_UID,
        gid=envvars.JOB_GID,
    ))
    return body


def status_job(input):
    try:
        api_response = api_batch_v1.read_namespaced_job_status(
            name=input["job_id"], namespace=input["namespace"], pretty=False
        )
        return "ok",api_response.status
    except ApiException as e:
        logger.info(
            "Exception when calling BatchV1Api->read_namespaced_job_status: {}\n".format(
                e
            )
        )
        return "error",None


def delete_job(input):
    try:
        api_response = api_batch_v1.delete_namespaced_job(
            name=input["job_id"],
            namespace=input["namespace"],
            body=client.V1DeleteOptions(
                propagation_policy="Foreground", grace_period_seconds=5
            ),
        )
        # logger.info("Job {} deleted".format(input["job_id"]))
    except ApiException as e:
        logger.error(
            "Exception when calling BatchV1Api->delete_namespaced_job: {}\n".format(e)
        )
    # try:
    #     api_response = api_v1.delete_namespaced_config_map(
    #         name=input["cm_name"],
    #         namespace=input["namespace"],
    #         body=client.V1DeleteOptions(
    #             propagation_policy="Foreground", grace_period_seconds=5
    #         ),
    #     )
    #     # logger.info("Config Map {} deleted".format(input["cm_name"]))
    # except ApiException as e:
    #     logger.error(
    #         "Exception when calling V1Api->delete_namespaced_configmap: {}\n".format(e)
    #     )

    return


def create_job(input):
    status = STATUS_OK
    msg = ''
    try:
        api_response = api_batch_v1.create_namespaced_job(
            namespace=input["namespace"], body=job(input)
        )
        # logger.info("Job {} created".format(input["configjob"]["metadata"]["jobId"]))
        create_configmap(input, job_uid=api_response.metadata.uid)
    except ApiException as e:
        logger.error(
            "Exception when calling BatchV1Api->create_namespaced_job: {}\n".format(e)
        )
        msg = "Exception when calling BatchV1Api->create_namespaced_job: {}\n".format(e)
        status = STATUS_ERROR
    return status, msg


def config_map(input, job_uid=''):
    keyfile = "configjob.yaml"
    meta = client.V1ObjectMeta(
        name=input["cm_name"],
        namespace=input["namespace"],
        labels={
            "task": input["job"],
            "username": input["configjob"]["metadata"]["username"],
        },
        owner_references=[client.V1OwnerReference(
            api_version='batch/v1', kind='Job',
            name=input["configjob"]["metadata"]["jobId"],
            uid=job_uid,
        )],
    )
    body = client.V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        metadata=meta,
        data={keyfile: yaml.dump(input["configjob"])},
    )
    return body


def create_configmap(input, job_uid=''):
    try:
        api_response = api_v1.create_namespaced_config_map(
            namespace=input["namespace"], body=config_map(input, job_uid=job_uid)
        )
        # logger.info("ConfigMap {} created".format(input["cm_name"]))

    except ApiException as e:
        logger.error(
            "Exception when calling CoreV1Api->create_namespaced_config_map: {}\n".format(
                e
            )
        )


if __name__ == "__main__":
    test_credentials()
    sys.exit(0)
