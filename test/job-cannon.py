import os
import requests
import time
import secrets
import itertools
import json

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


ra_decs = [
    [21.58813, 3.48611],
    [21.59813, 3.58611],
    [21.57813, 3.68611],
    [21.57213, 3.78611],
    [36.60840, -15.68889],
    [36.63840, -15.66889],
    [36.66840, -15.68889],
    [36.67840, -15.65889],
    [46.27566, -34.25000],
    [46.28566, -34.25500],
    [46.29566, -34.25600],
    [46.27566, -34.25900]
]

# These coadd IDs are valid for release Y3A2:
#     SELECT COADD_OBJECT_ID FROM Y3_GOLD_2_2 where ROWNUM < 20
# Coadd IDs from the Y6A1 release can be found by:
#     SELECT COADD_OBJECT_ID FROM Y6_GOLD_1_1 where ROWNUM < 20
coadds = [
    '61407318',
    '61407322',
    '61407330',
    '61407332',
    '61407340',
    '61407380',
    '61407409',
    '61407410',
    '61407412',
    '61407424',
    '61407430',
    '61407435',
    '61407478',
    '61407507',
    '61407519',
    '61407550',
    '61407559',
    '61407563',
    '61407582'
]

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


def launch_multiple_jobs(job_type='test', randomize_each=False):
    job_idx = 0
    loop_idx = 0
    data = None
    while job_idx < config['max_jobs']:
        # Submit job with 50% probability per second
        if secrets.choice(range(0, 100)) < config['launch_probability']:
            # Job type: test
            if job_type == 'test':
                # Select a random job duration
                duration = secrets.choice(
                    range(config['duration_min'], config['duration_max']))
                if not data or randomize_each:
                    data = {
                        'username': config['username'],
                        'job': 'test',
                        'time': duration
                    }
            # Job type: cutout
            elif job_type == 'cutout':
                # Choose random set of colors for FITS
                colors_fits = []
                for i in range(0,secrets.choice(range(0,8))):
                    colors_fits.append(secrets.choice(list('grizy')))
                colors_fits = ','.join(colors_fits)
                # Choose from combinations of
                colors_rgb = []
                combinations = []
                for combination in list(itertools.combinations(list('grizy'), 3)):
                    combinations.append(combination)
                colors_rgb = ','.join(secrets.choice(combinations))

                if not data or randomize_each:
                    data = {
                        'username': config['username'],
                        'job': 'cutout',
                        'db': 'dessci',
                        'xsize': secrets.choice([0.1,0.5,1.0,5.0]),
                        'ysize': secrets.choice([0.1,0.5,1.0,5.0]),
                        'make_fits': secrets.choice(['true', 'false']),
                        'make_pngs': secrets.choice(['true', 'false']),
                        'make_tiffs': secrets.choice(['true', 'false']),
                        'make_rgb_lupton': secrets.choice(['true', 'false']),
                        'make_rgb_stiff': secrets.choice(['true', 'false']),
                        'return_list': secrets.choice(['true', 'false']),
                        'colors_fits': colors_fits,
                        'colors_rgb': colors_rgb,
                    }

                    # Select either RA/DEC
                    if secrets.choice(['coadds', 'ra_decs']) == 'ra_decs':
                        data['release'] = secrets.choice(['Y6A1', 'Y3A2'])
                        ra_dec = secrets.choice(ra_decs)
                        data['ra'] = ra_dec[0]
                        data['dec'] = ra_dec[1]
                    # or Coadd IDs
                    else:
                        data['release'] = secrets.choice(['Y3A2'])
                        data['coadd'] = secrets.choice(coadds)

            # Submit job
            r = requests.put(
                '{}/job/submit'.format(config['apiBaseUrl']),
                data=data,
                headers={'Authorization': 'Bearer {}'.format(
                    config['auth_token'])}
            )
            print(json.dumps(data, indent=2))
            if r.json()['status'] == 'ok':
                job_idx = job_idx + 1
                job_id = r.json()['jobid']
                print('Job "{}" started at cycle {}.'.format(job_id, loop_idx))
            else:
                print(r.json()['message'])
                print('Error submitting job at cycle {}'.format(loop_idx))

        loop_idx = loop_idx + 1
        time.sleep(config['launch_separation'])

if __name__ == '__main__':
    login()
    launch_multiple_jobs(job_type='cutout', randomize_each=True)
