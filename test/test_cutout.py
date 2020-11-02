import os
import sys
import requests
import time
import json

username = os.environ['CUTOUT_USER']
password = os.environ['CUTOUT_PASS']
base_url = os.environ['CUTOUT_BASEURL']
position_file = os.environ['CUTOUT_POSITION_FILE']
db = os.environ['CUTOUT_DB']
release = os.environ['CUTOUT_RELEASE']

config = {
    'auth_token': '',
    'apiBaseUrl': '{}/desaccess/api'.format(base_url),
    'filesBaseUrl': '{}/files-desaccess/'.format(base_url),
    'username': username,
    'password': password,
    'database': db,
    'release': release,
    'positions_file': position_file,
}

def login():
    """Obtains an auth token using the username and password credentials for a given database.
    """
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
    config['auth_token'] = r.json()['token']
    return config['auth_token']

def submit_cutout_job():
    """Submits a cutout job and returns the complete server response which includes the job ID."""

    with open(os.path.join(os.path.dirname(__file__), 'cutout_csv_tests', config['positions_file']), 'r') as csvfile:
        positions = csvfile.read()
    # Specify API request parameters
    data = {
        'db': config['database'],
        'release': config['release'],
        'xsize': 1.5,
        'ysize': 0.5,
        'make_fits': True,
        'make_rgb_lupton': True,
        'make_rgb_stiff': True,
        'return_list': False,
        'colors_fits': 'y',
        'rgb_stiff_colors': 'riz',
        'rgb_lupton_colors': 'izy',
        'positions': positions,
    }

    # Submit job
    r = requests.put(
        '{}/job/cutout'.format(config['apiBaseUrl']),
        data=data,
        timeout=None,
        headers={'Authorization': 'Bearer {}'.format(config['auth_token'])}
    )
    response = r.json()
    # print(json.dumps(response, indent=2))
    
    if response['status'] == 'ok':
        job_id = response['jobid']
        print('Job "{}" submitted.'.format(job_id))
        # Refresh auth token
        config['auth_token'] = response['new_token']
    else:
        job_id = None
        print('Error submitting job: '.format(response['message']))
    
    return response

def get_job_status(job_id):
    """Returns the current status of the job identified by the unique job_id."""

    r = requests.post(
        '{}/job/status'.format(config['apiBaseUrl']),
        data={
            'job-id': job_id
        },
        headers={'Authorization': 'Bearer {}'.format(config['auth_token'])}
    )
    response = r.json()
    # Refresh auth token
    config['auth_token'] = response['new_token']
    # print(json.dumps(response, indent=2))
    return response

def download_job_files(url, outdir):
    os.makedirs(outdir, exist_ok=True)
    r = requests.get('{}/json'.format(url))
    for item in r.json():
        if item['type'] == 'directory':
            suburl = '{}/{}'.format(url, item['name'])
            subdir = '{}/{}'.format(outdir, item['name'])
            download_job_files(suburl, subdir)
        elif item['type'] == 'file':
            data = requests.get('{}/{}'.format(url, item['name']))
            with open('{}/{}'.format(outdir, item['name']), "wb") as file:
                file.write(data.content)

    response = r.json()
    return response

def list_downloaded_files(download_dir):
    for dirpath, dirnames, filenames in os.walk(download_dir):
        for filename in filenames:
            print(os.path.join(dirpath, filename))

if __name__ == '__main__':
    # Authenticate and store the auth token for subsequent API calls
    try:
        print('Logging in as user "{}" ("{}") and storing auth token...'.format(config['username'], config['database']))
        login()
    except:
        print('Login failed.')
        sys.exit(1)

    job_type = 'cutout'

    print('Submitting cutout job...')
    response = submit_cutout_job()
    if response['status'] == 'ok':
        # Store the unique job ID for the new job
        job_id = response['jobid']
        print('New job submitted: {}'.format(job_id))
    else:
        print('Response: {}'.format(json.dumps(response, indent=2)))

    print('Polling status of job "{}"...'.format(job_id), end='')
    job_status = ''
    while job_status != 'ok':
        # Fetch the current job status
        response = get_job_status(job_id)
        # Quit polling if there is an error getting a status update
        if response['status'] != 'ok':
            break
        job_status = response['jobs'][0]['job_status']
        if job_status == 'success' or job_status == 'failure':
            print('\nJob completed with status: {}'.format(job_status))
            break
        else:
            # Display another dot to indicate that polling is still active
            print('.', end='', sep='', flush=True)
        time.sleep(3)

    print('Complete job status details:')
    print(json.dumps(response, indent=2))

    # # If successful, display job results
    # if job_status == 'success':

    #     # Download single compressed archive file containing all job files
    #     job_archive_filename = '{}.tar.gz'.format(job_id)
    #     job_archive_file_url = '{}/{}/{}/{}'.format(config['filesBaseUrl'], config['username'], 'cutout', job_archive_filename)
    #     data = requests.get(job_archive_file_url)
    #     with open('./{}'.format(job_archive_filename), "wb") as file:
    #         file.write(data.content)
    #     print('Job archive file "{}" downloaded.'.format(job_archive_filename))

    #     # Construct the job file download URL
    #     job_url = '{}/{}/{}/{}'.format(config['filesBaseUrl'], config['username'], job_type, job_id)
    #     download_dir = './{}'.format(job_id)
    #     # Download each raw job file sequentially to a subfolder of the working directory
    #     download_job_files(job_url, download_dir)
    #     print('Files for job "{}" downloaded to "{}"'.format(job_id, download_dir))
    #     list_downloaded_files(download_dir)
    # else:
    #     print('The job "{}" failed.'.format(job_id))