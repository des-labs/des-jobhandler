import os
import requests
import time
import secrets

#
# This script is designed to be executed outside the JobHandler as an independent
# client. Create a file to define the environment variables as shown below,
# needed and source it prior to executing the script.
#
'''
    export JOB_CANNON_API_BASE_URL=https://[dev_domain]/easyweb/api
    export JOB_CANNON_USERNAME=your_username
    export JOB_CANNON_PASSWORD=your_password
    export JOB_CANNON_DURATION_MIN=60
    export JOB_CANNON_DURATION_MAX=90
    export JOB_CANNON_MAX_JOBS=30
    export JOB_CANNON_LAUNCH_SEPARATION=0.1
    export JOB_CANNON_MAX_LAUNCH_PROBABILITY=100
'''

# Import credentials and config from environment variables
config = {
    'auth_token': '',
    'apiBaseUrl': os.environ['JOB_CANNON_API_BASE_URL'],
    'username': os.environ['JOB_CANNON_USERNAME'],
    'password': os.environ['JOB_CANNON_PASSWORD'],
    'database': 'dessci',
    'duration_min': 60*2,
    'duration_max': 60*5,
    'launch_probability': 100,
    'launch_separation': 0.5,
    'max_jobs': 50
}
# All or nothing customization from environment variables
try:
    config['duration_min'] = int(os.environ['JOB_CANNON_DURATION_MIN'])
    config['duration_max'] = int(os.environ['JOB_CANNON_DURATION_MAX'])
    config['launch_probability'] = int(
        os.environ['JOB_CANNON_MAX_LAUNCH_PROBABILITY'])
    config['launch_separation'] = float(
        os.environ['JOB_CANNON_LAUNCH_SEPARATION'])
    config['max_jobs'] = int(os.environ['JOB_CANNON_MAX_JOBS'])
except:
    pass


def login():
    # Login to obtain an auth token
    r = requests.post(
        '{}/login'.format(config['apiBaseUrl']),
        data={
            'username': config['username'],
            'password': config['password'],
            'database': config['database']
        }
    )
    # Store the JWT auth token
    token = r.json()['token']
    config['auth_token'] = token
    return token


def submit_test_job():
    # Submit a test job
    test_duration = 10  # seconds
    r = requests.put(
        '{}/job/submit'.format(config['apiBaseUrl']),
        data={
            'username': config['username'],
            'job': 'test',
            'time': test_duration
        },
        headers={'Authorization': 'Bearer {}'.format(config['auth_token'])}
    )
    job_id = r.json()['jobid']
    print(r.text)
    return job_id


def monitor_test_job(job_id):
    # Monitor the test job status
    max_loops = 5
    idx = 0
    while idx < max_loops:
        idx = idx + 1

        r = requests.post(
            '{}/job/status'.format(config['apiBaseUrl']),
            data={
                'job-id': job_id
            },
            headers={'Authorization': 'Bearer {}'.format(config['auth_token'])}
        )
        # print(r.text)
        r = r.json()
        status = r['jobs'][0]['job_status']
        print('Status: {}'.format(status))
        if status == 'success' or status == 'failure':
            break
        time.sleep(3)


def launch_multiple_jobs(job_type='test'):
    job_idx = 0
    loop_idx = 0
    while job_idx < config['max_jobs']:
        # Submit job with 50% probability per second
        if secrets.choice(range(0, 100)) < config['launch_probability']:
            if job_type == 'test':
                # Select a random job duration
                duration = secrets.choice(
                    range(config['duration_min'], config['duration_max']))
                data = {
                    'username': config['username'],
                    'job': 'test',
                    'time': duration
                }
            elif job_type == 'cutout':
                # Select a random job duration
                data = {
                    'username': config['username'],
                    'job': 'cutout',
                    'ra': secrets.choice([0.1,0.2,0.3,0.4,0.5]),
                    'dec': secrets.choice([0.1,0.2,0.3,0.4,0.5]),
                    'make_fits': 'true',
                    'xsize': secrets.choice([0.1,0.5,1.0,5.0]),
                    'ysize': secrets.choice([0.1,0.5,1.0,5.0]),
                    'colors': 'g,r,i',
                    'release': 'Y6A1'
                }

            r = requests.put(
                '{}/job/submit'.format(config['apiBaseUrl']),
                data=data,
                headers={'Authorization': 'Bearer {}'.format(
                    config['auth_token'])}
            )
            if r.json()['status'] == 'ok':
                job_idx = job_idx + 1
                job_id = r.json()['jobid']
                print('Job "{}" started at cycle {}.'.format(job_id, loop_idx))
            else:
                print('Error submitting job at cycle {}'.format(loop_idx))
        loop_idx = loop_idx + 1
        time.sleep(config['launch_separation'])


if __name__ == '__main__':
    login()
    # job_id = submit_test_job()
    # monitor_test_job(job_id)
    launch_multiple_jobs(job_type='cutout')
