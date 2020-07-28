import logging
import os
from jinja2 import Template
import yaml
import jobutils
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import envvars

STATUS_OK = 'ok'
STATUS_ERROR = 'error'

logger = logging.getLogger(__name__)

config.load_incluster_config()

api_v1 = client.CoreV1Api()
apps_v1_api = client.AppsV1Api()
networking_v1_beta1_api = client.NetworkingV1beta1Api()
namespace = jobutils.get_namespace()

def create_deployment(apps_v1_api, username):
    name = 'jlab-{}'.format(username)
    try:
        container = client.V1Container(
            name=name,
            image="jupyter/scipy-notebook:latest",
            image_pull_policy="Always",
            ports=[client.V1ContainerPort(container_port=8888)],
            volume_mounts=[client.V1VolumeMount(
                name='jupyter-config',
                mount_path="/home/jovyan/.jupyter/"
            )]
        )
        volume = client.V1Volume(
            name='jupyter-config',
            config_map=client.V1ConfigMapVolumeSource(
                name=name,
                items=[client.V1KeyToPath(
                    key=name,
                    path="jupyter_notebook_config.py"
                )]
            )
        )
        # Template
        template = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(labels={"app": name}),
                spec=client.V1PodSpec(
                    containers=[container],
                    volumes=[volume]
                )
            )
        # Spec
        spec = client.V1DeploymentSpec(
            replicas=1,
            template=template,
            selector=client.V1LabelSelector(
                match_labels=dict({'app': name})
            )
        )
        # Deployment
        deployment = client.V1Deployment(
            api_version="apps/v1",
            kind="Deployment",
            metadata=client.V1ObjectMeta(name=name),
            spec=spec)
        # Creation of the Deployment in specified namespace
        apps_v1_api.create_namespaced_deployment(
            namespace=namespace, body=deployment
        )
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)


def create_service(core_v1_api, username):
    name = 'jlab-{}'.format(username)
    try:
        body = client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=client.V1ObjectMeta(
                name=name
            ),
            spec=client.V1ServiceSpec(
                selector={"app": name},
                ports=[client.V1ServicePort(
                    port=8888,
                    target_port=8888
                )]
            )
        )
        # Creation of the Service in specified namespace
        core_v1_api.create_namespaced_service(namespace=namespace, body=body)
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)


def create_ingress(networking_v1_beta1_api, username):
    name = 'jlab-{}'.format(username)
    try:
        body = client.NetworkingV1beta1Ingress(
            api_version="networking.k8s.io/v1beta1",
            kind="Ingress",
            metadata=client.V1ObjectMeta(name=name, annotations={
                'kubernetes.io/ingress.class': 'trans'
            }),
            spec=client.NetworkingV1beta1IngressSpec(
                tls=[
                    client.ExtensionsV1beta1IngressTLS(
                        hosts=[
                            envvars.BASE_DOMAIN
                        ],
                        secret_name=envvars.TLS_SECRET
                    )
                ],
                rules=[client.NetworkingV1beta1IngressRule(
                    host=envvars.BASE_DOMAIN,
                    http=client.NetworkingV1beta1HTTPIngressRuleValue(
                        paths=[client.NetworkingV1beta1HTTPIngressPath(
                            path="/jlab/{}".format(username),
                            backend=client.NetworkingV1beta1IngressBackend(
                                service_port=8888,
                                service_name=name)

                        )]
                    )
                )
                ]
            )
        )
        # Creation of the Ingress in specified namespace
        networking_v1_beta1_api.create_namespaced_ingress(
            namespace=namespace,
            body=body
        )
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)

def delete_deployment(api_instance, username):
    name = 'jlab-{}'.format(username)
    try:
        api_response = api_instance.delete_namespaced_deployment(
            name=name,
            namespace=namespace,
            body=client.V1DeleteOptions(
                propagation_policy='Foreground',
                grace_period_seconds=5))
        logger.info("Deployment deleted. status='%s'" % str(api_response.status))
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)


def delete_service(api_instance, username):
    name = 'jlab-{}'.format(username)
    try:
        api_response = api_instance.delete_namespaced_service(
            name=name,
            namespace=namespace,
            body={}
        )
        logger.info("Service deleted. status='%s'" % str(api_response.status))
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)


def delete_ingress(api_instance, username):
    name = 'jlab-{}'.format(username)
    try:
        api_response = api_instance.delete_namespaced_ingress(
            name=name,
            namespace=namespace,
            body={}
        )
        logger.info("Ingress deleted. status='%s'" % str(api_response.status))
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)

def delete_config_map(api_instance, username):
    name = 'jlab-{}'.format(username)
    try:
        api_response = api_instance.delete_namespaced_config_map(
            name=name,
            namespace=namespace,
            body={}
        )
        logger.info("Ingress deleted. status='%s'" % str(api_response.status))
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)

def create_config_map(api_v1, username, base_path, token):
    name = 'jlab-{}'.format(username)
    try:
        meta = client.V1ObjectMeta(
            name=name,
            namespace=namespace,
        )
        body = client.V1ConfigMap(
            api_version="v1",
            kind="ConfigMap",
            metadata=meta,
            data={
                name: '''c.NotebookApp.token = u'{}'
c.NotebookApp.base_url = '{}'
'''.format(token, base_path)},
        )

        api_response = api_v1.create_namespaced_config_map(
            namespace=namespace, 
            body=body
        )
        logger.info("ConfigMap created")
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)


def delete(username):
    error_msg = ''
    try:
        delete_config_map(api_v1, username)
        delete_deployment(apps_v1_api, username)
        delete_service(api_v1, username)
        delete_ingress(networking_v1_beta1_api, username)
    except Exception as e:
        error_msg = str(e).strip()
        logger.error(error_msg)
    return error_msg
    
def deploy(username, base_path, token):
    error_msg = ''
    try:
        create_config_map(api_v1, username, base_path, token)
        create_deployment(apps_v1_api, username)
        create_service(api_v1, username)
        create_ingress(networking_v1_beta1_api, username)
    except Exception as e:
        error_msg = str(e).strip()
        logger.error(error_msg)
    return error_msg

def create(username, base_path, token):
    logger.info('Deleting existing Kubernetes resources...')
    error_msg = delete(username)
    if error_msg == '':
        logger.info('Deploying new Kubernetes resources...')
        error_msg = deploy(username, base_path, token)
    return error_msg

def status(username):
    error_msg = ''
    ready_replicas = -1
    replicas = 0
    config_map = {}
    token = ''
    name = 'jlab-{}'.format(username)
    try:
        api_response = apps_v1_api.read_namespaced_deployment_status(namespace=namespace,name=name)
        logger.info('Deployment status: {}'.format(api_response))
        ready_replicas = api_response.status.ready_replicas
        replicas = api_response.status.replicas

        api_response = api_v1.read_namespaced_config_map(namespace=namespace,name=name)
        logger.info('Config map: {}'.format(api_response))
        config_map = api_response.data
        token = config_map[name].split("'")[1]
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)
    return ready_replicas, token, error_msg