import logging
import os
from jinja2 import Template
import yaml
import jobutils
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import envvars
import pytz
import datetime
import requests

STATUS_OK = 'ok'
STATUS_ERROR = 'error'

logger = logging.getLogger(__name__)

config.load_incluster_config()

api_v1 = client.CoreV1Api()
apps_v1_api = client.AppsV1Api()
networking_v1_beta1_api = client.NetworkingV1beta1Api()
namespace = jobutils.get_namespace()

def create_deployment(apps_v1_api, username, token, gpu):
    name = 'jlab-{}'.format(username)
    try:
        init_container = client.V1Container(
            name='{}-init'.format(name),
            image="ubuntu:18.04",
            image_pull_policy="IfNotPresent",
            command=["/bin/sh"],
            args=["-c", "chown 1001:1001 /persistent_volume"],
            volume_mounts=[
                client.V1VolumeMount(
                    name='persistent-volume',
                    mount_path="/persistent_volume",
                    sub_path='{}/jupyter'.format(username)
                )
            ]
        )
        if gpu == True:
            limits = {
                'nvidia.com/gpu': 1
            }
        else:
            limits = None
        container = client.V1Container(
            name=name,
            image=envvars.DOCKER_IMAGE_JLAB_SERVER,
            resources=client.V1ResourceRequirements(
                limits=limits
            ),
            image_pull_policy="Always",
            ports=[client.V1ContainerPort(container_port=8888)],
            env=[
                client.V1EnvVar(
                    name='DES_USER',
                    value=username
                ),
                client.V1EnvVar(
                    name='PIP_TARGET',
                    value='/home/jovyan/work/.pip'
                ),
                client.V1EnvVar(
                    name='PYTHONPATH',
                    value='/home/jovyan/work/.pip'
                )
            ],
            volume_mounts=[
                client.V1VolumeMount(
                    name='jupyter-config',
                    mount_path="/home/jovyan/.jupyter/"
                ),
                client.V1VolumeMount(
                    name='persistent-volume',
                    mount_path="/home/jovyan/jobs/cutout",
                    sub_path='{}/cutout'.format(username)
                ),
                client.V1VolumeMount(
                    name='persistent-volume',
                    mount_path="/home/jovyan/jobs/query",
                    sub_path='{}/query'.format(username)
                ),
                client.V1VolumeMount(
                    name='persistent-volume',
                    mount_path="/home/jovyan/work",
                    sub_path='{}/jupyter'.format(username)
                )
            ]
        )
        volume_config = client.V1Volume(
            name='jupyter-config',
            config_map=client.V1ConfigMapVolumeSource(
                name=name,
                items=[client.V1KeyToPath(
                    key=name,
                    path="jupyter_notebook_config.py"
                )]
            )
        )
        volume_persistent = client.V1Volume(
            name='persistent-volume',
            persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                claim_name=envvars.PVC_NAME_BASE
            )
        )
        # Template
        template = client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(labels={"app": name}),
                spec=client.V1PodSpec(
                    image_pull_secrets=[
                        client.V1LocalObjectReference(
                            name='registry-auth'
                        )
                    ],
                    init_containers=[
                        init_container
                    ],
                    containers=[
                        container
                    ],
                    volumes=[
                        volume_config,
                        volume_persistent
                    ],
                    node_selector = {'gpu': '{}'.format(gpu).lower()}
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
        api_response = apps_v1_api.create_namespaced_deployment(
            namespace=namespace, body=deployment
        )
        # logger.info('Deployment created:\n{}'.format(api_response))
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
        # TODO: Improve this parameterization so that no cluster-specific details are hard-coded
        body = client.NetworkingV1beta1Ingress(
            api_version="networking.k8s.io/v1beta1",
            kind="Ingress",
            metadata=client.V1ObjectMeta(name=name, annotations={
                'kubernetes.io/ingress.class': envvars.INGRESS_CLASS_JLAB_SERVER
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
                            path="{}/jlab/{}".format(envvars.FRONTEND_BASE_PATH, username),
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
        # logger.info("Deployment deleted. status='%s'" % str(api_response.status))
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
        # logger.info("Service deleted. status='%s'" % str(api_response.status))
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
        # logger.info("Ingress deleted. status='%s'" % str(api_response.status))
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
        # logger.info("Ingress deleted. status='%s'" % str(api_response.status))
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
        # logger.info("ConfigMap created")
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)


def delete(username):
    error_msg = ''
    try:
        # sync_to_user_folder(username)
        delete_config_map(api_v1, username)
        delete_deployment(apps_v1_api, username)
        delete_service(api_v1, username)
        delete_ingress(networking_v1_beta1_api, username)
    except Exception as e:
        error_msg = str(e).strip()
        logger.error(error_msg)
    return error_msg
    
def deploy(username, base_path, token, gpu):
    error_msg = ''
    try:
        create_config_map(api_v1, username, base_path, token)
        create_deployment(apps_v1_api, username, token, gpu)
        create_service(api_v1, username)
        create_ingress(networking_v1_beta1_api, username)
    except Exception as e:
        error_msg = str(e).strip()
        logger.error(error_msg)
    return error_msg

def create(username, base_path, token, gpu):
    # logger.info('Deleting existing Kubernetes resources...')
    error_msg = delete(username)
    if error_msg == '':
        # logger.info('Deploying new Kubernetes resources...')
        error_msg = deploy(username, base_path, token, gpu)
    return error_msg

def status(username):
    error_msg = ''
    response = {
        'unavailable_replicas': -1,
        'ready_replicas': -1,
        'token': '',
        'creation_timestamp': '',
        'latest_condition_type': 'Unknown',
    }
    name = 'jlab-{}'.format(username)
    try:
        api_response = apps_v1_api.read_namespaced_deployment_status(namespace=namespace,name=name)
        response['ready_replicas'] = api_response.status.ready_replicas
        response['unavailable_replicas'] = api_response.status.unavailable_replicas
        last_transition_time = None
        for condition in api_response.status.conditions:
            if last_transition_time == None or condition.last_transition_time > last_transition_time:
                last_transition_time = condition.last_transition_time
                response['latest_condition_type'] = condition.type
        response['latest_condition_type'] = api_response.status.conditions[0].type
        response['creation_timestamp'] = api_response.metadata.creation_timestamp

        api_response = api_v1.read_namespaced_config_map(namespace=namespace,name=name)
        # Parse the ConfigMap based on its well-defined construction
        # logger.info('Config map: {}'.format(api_response))
        config_map = api_response.data
        response['token'] = config_map[name].split("'")[1]
    except ApiException as e:
        response['latest_condition_type'] = ''
        error_msg = str(e).strip()
        logger.error(error_msg)
    return response, error_msg

def prune(users, current_time):
    error_msg = ''
    pruned = []
    for username in users:
        name = 'jlab-{}'.format(username)
        try:
            api_response = api_v1.read_namespaced_config_map(namespace=namespace,name=name)
            # Parse the ConfigMap based on its well-defined construction
            config_map = api_response.data
            token = config_map[name].split("'")[1]
            # Get the list of running JupyterLab kernels using the JupyterLab API
            r = requests.get(
                '{}/jlab/{}/api/kernels'.format(envvars.FRONTEND_BASE_URL, username),
                params={
                    'token': token
                }
            )
            kernels = r.json()
            # Iterate through the list of kernels and find the most recently active
            last_activity = None
            for k in kernels:
                try:
                    last_activity_k = datetime.datetime.strptime(k['last_activity'], '%Y-%m-%dT%H:%M:%S.%fZ')
                    if not last_activity or last_activity_k > last_activity:
                        last_activity = last_activity_k
                except Exception as e:
                    error_msg = str(e).strip()
                    logger.error(error_msg) 
                    pass
            # If an active kernel was discovered, delete the JupyterLab server if it has been idle over 24 hours
            if last_activity:
                # Delete the deployment if it has been idle over 24 hours
                last_activity_tz = pytz.utc.localize(last_activity)
                # logger.info('Seconds idle: {}'.format((current_time - last_activity_tz).seconds))
                if (current_time - last_activity_tz).seconds > 24*60*60:
                    error_msg = delete(username)
                    pruned.append(username)
            # If no active kernel was found, delete the JupyterLab deployment if it was created over 24 hours ago
            else:
                try:
                    api_response = apps_v1_api.read_namespaced_deployment_status(namespace=namespace,name=name)
                    creation_timestamp = api_response.metadata.creation_timestamp
                    current_time = pytz.utc.localize(current_time)
                    # Delete the deployment if it has been online over 24 hours
                    if (current_time - creation_timestamp).seconds > 24*60*60:
                        error_msg = delete(username)
                        pruned.append(username)
                except ApiException as e:
                    error_msg = str(e).strip()
                    logger.error(error_msg)
        except Exception as e:
            error_msg = str(e).strip()
            logger.error(error_msg)
    return pruned, error_msg
