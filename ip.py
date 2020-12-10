import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from collections import Counter

logger = logging.getLogger(__name__)

config.load_incluster_config()

api_v1 = client.CoreV1Api()

def query_pod_logs(api_v1=api_v1, cluster='pub'):
    if cluster == 'pub':
        release = 'nginx-ingress-nginx'
        namespace = 'nginx-ingress'
    elif cluster == 'prod':
        release='nginx-ingress-class-deslabs'
        namespace="nginx-ingress"
    else:
        cluster='dev'
        release='nginx-ingress-trans'
        namespace='desapps'

    # Getting pod name based on public or private infrastructure
    pods = api_v1.list_namespaced_pod(namespace, watch = False,
        label_selector="component=controller,release={release}".format(release=release)
    )
    
    pod_name = pods.items[0].metadata.name
    
    ips = []
    try:
        # Reading of the nginx controller in specified namespace
        api_response = api_v1.read_namespaced_pod_log(
            namespace=namespace, name = pod_name)
        
        # Getting IPs from api_response
        for line in api_response.split('\n'):
            if '/desaccess/api/login' in line:
                ip = line.split(' ')[0]
                ips.append(ip)    

        # Getting count of unique ips
        counter_unique_ips = Counter(ips)
        return counter_unique_ips
       
    except ApiException as e:
        error_msg = str(e).strip()
        logger.error(error_msg)