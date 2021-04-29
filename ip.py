import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from collections import Counter

logger = logging.getLogger(__name__)

config.load_incluster_config()

api_v1 = client.CoreV1Api()

def query_pod_logs(api_v1=api_v1, cluster='pub', namespace='traefik'):
    if cluster == 'pub':
        instance = 'traefik-des-ncsa'
    elif cluster == 'prod':
        instance = 'traefik-deslabs-ncsa'

    # Getting pod name based on public or private infrastructure
    pods = api_v1.list_namespaced_pod(namespace, watch = False,
        label_selector="instance={instance}".format(instance=instance)
    )
    logger.info(pods)    
    pod_name = pods.items[0].metadata.name
    logger.info(pod_name)
    
    ips = []
    # try:
    # Reading of the nginx controller in specified namespace
    api_response = api_v1.read_namespaced_pod_log(
        namespace=namespace, name = pod_name)
    logger.info(api_response)        
    # Getting IPs from api_response
    for line in api_response.split('\n'):
        if '/desaccess/api/login' in line:
            ip = line.split(' ')[0]
            ips.append(ip)    

    # Getting count of unique ips
    counter_unique_ips = Counter(ips)
    return counter_unique_ips
       
    #except ApiException as e:
    #    error_msg = str(e).strip()
    #    logger.error(error_msg)
