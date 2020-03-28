import logging
import yaml
import sys
import os
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from jinja2 import Template

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
    '''
    vmounts = client.V1VolumeMount(
        name="config-volume",
        mount_path="/home/worker/configjob.yaml",
        sub_path="configjob.yaml",
    )
    volume = client.V1Volume(
        name="config-volume",
        config_map=client.V1ConfigMapVolumeSource(name=input["cm_name"]),
    )
    container = client.V1Container(
        name=input["job"],
        image=input["image"],
        command=input["command"],
        volume_mounts=[vmounts],
    )
    imagePullSecret = client.V1LocalObjectReference(
        # TODO: Replace this hard-coded secret reference with an environment variable value
        name='registry-auth'
    )
    podspec = client.V1PodSpec(
        containers=[container], restart_policy="Never", volumes=[volume], image_pull_secrets=[imagePullSecret]
    )
    template = client.V1PodTemplateSpec(spec=podspec)
    jobspec = client.V1JobSpec(
        active_deadline_seconds=600,
        ttl_seconds_after_finished=600,
        template=template,
        backoff_limit=2,
    )
    jobmeta = client.V1ObjectMeta(name=input["job_name"], namespace=input["namespace"])
    body = client.V1Job(
        api_version="batch/v1", kind="Job", metadata=jobmeta, spec=jobspec
    )
    '''

    with open(os.path.join(os.path.dirname(__file__), "job.tpl.yaml")) as f:
        templateText = f.read()

    template = Template(templateText)
    body = yaml.safe_load(template.render(
        name=input["job_name"],
        namespace=input["namespace"],
        backoffLimit=2,
        hostNetwork=input["host_network"],
        activeDeadlineSeconds=24*60*60, # No Job is allowed to run beyond 24 hours.
        ttlSecondsAfterFinished=600,
        container_name=input["job"],
        image=input["image"],
        command=input["command"],
        configmap_name=input["cm_name"],
        pvc_name=input["configjob"]["metadata"]["persistentVolumeClaim"],
        username=input["configjob"]["metadata"]["username"],
    ))

    return body


def status_job(input):
    try:
        api_response = api_batch_v1.read_namespaced_job_status(
            name=input["job_name"], namespace=input["namespace"], pretty=False
        )
        logger.info(api_response.status)
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
            name=input["job_name"],
            namespace=input["namespace"],
            body=client.V1DeleteOptions(
                propagation_policy="Foreground", grace_period_seconds=5
            ),
        )
        logger.info("Job {} deleted".format(input["job_name"]))
    except ApiException as e:
        logger.error(
            "Exception when calling BatchV1Api->delete_namespaced_job: {}\n".format(e)
        )
    try:
        api_response = api_v1.delete_namespaced_config_map(
            name=input["cm_name"],
            namespace=input["namespace"],
            body=client.V1DeleteOptions(
                propagation_policy="Foreground", grace_period_seconds=5
            ),
        )
        logger.info("Config Map {} deleted".format(input["cm_name"]))
    except ApiException as e:
        logger.error(
            "Exception when calling V1Api->delete_namespaced_configmap: {}\n".format(e)
        )

    return


def create_job(input):
    try:
        api_response = api_batch_v1.create_namespaced_job(
            namespace=input["namespace"], body=job(input)
        )
        logger.info("Job {} created".format(input["job_name"]))
    except ApiException as e:
        logger.error(
            "Exception when calling BatchV1Api->create_namespaced_job: {}\n".format(e)
        )
    return


def config_map(input):
    keyfile = "configjob.yaml"
    meta = client.V1ObjectMeta(name=input["cm_name"], namespace=input["namespace"])
    body = client.V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        metadata=meta,
        data={keyfile: yaml.dump(input["configjob"])},
    )
    return body


def create_configmap(input):
    try:
        api_response = api_v1.create_namespaced_config_map(
            namespace=input["namespace"], body=config_map(input)
        )
        logger.info("ConfigMap {} created".format(input["cm_name"]))

    except ApiException as e:
        logger.error(
            "Exception when calling CoreV1Api->create_namespaced_config_map: {}\n".format(
                e
            )
        )


if __name__ == "__main__":
    test_credentials()
    sys.exit(0)
