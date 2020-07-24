#!/usr/bin/env python3

import os
import sys
import requests
import time
import json

try:
    # Import credentials and config from environment variables
    config = {
        'auth_token': '',
        'apiBaseUrl': os.environ['DESACCESS_API_BASE_URL'],
        'filesBaseUrl': os.environ['DESACCESS_FILES_BASE_URL'],
        'username': os.environ['DESACCESS_USERNAME'],
        'password': os.environ['DESACCESS_PASSWORD'],
        'database': os.environ['DESACCESS_DATABASE']
    }
except:
    print('''
# Create a file to define the environment variables as shown below and source it prior to executing this script.

cat <<EOF > $HOME/.desaccess-credentials

#!/bin/sh

export DESACCESS_API_BASE_URL=https://deslabs.ncsa.illinois.edu/desaccess/api
export DESACCESS_FILES_BASE_URL=https://deslabs.ncsa.illinois.edu/files-desaccess
export DESACCESS_USERNAME=your_username
export DESACCESS_PASSWORD=your_password
export DESACCESS_DATABASE=dessci

EOF

source $HOME/.desaccess-credentials

{}
'''.format(sys.argv[0])
    )
    sys.exit(1)

# Define some example RA/DEC coordinates
ra_decs = [
    [21.58813, 3.48611],
    [46.27566, -34.25900]
]

# These coadd IDs are valid for release Y3A2:
#     SELECT COADD_OBJECT_ID FROM Y3_GOLD_2_2 where ROWNUM < 20
# Coadd IDs from the Y6A1 release can be found by:
#     SELECT COADD_OBJECT_ID FROM Y6_GOLD_1_1 where ROWNUM < 20
coadds = [
    '61407318',
    '61407582'
]

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
    """Submits a query job and returns the complete server response which includes the job ID."""

    # Specify API request parameters
    data = {
        'username': config['username'],
        'job': 'cutout',
        # The database must be either 'dessci' or 'desoper'
        'db': config['database'],
        'xsize': 1.5,
        'ysize': 0.5,
        'make_fits': True,
        'make_rgb_lupton': True,
        'make_rgb_stiff': True,
        'return_list': False,
        'colors_fits': 'g,r,i,z,y',
        'colors_rgb': 'g,r,z',
        # If coordinates are used, the release must be either 'Y6A1' or 'Y3A2' 
        'ra': 21.58813,
        'dec': 3.48611,
        # If coadd ID is used, the release must be 'Y3A2'. If both ra/dec and coadd are specified, coadd is ignored.
        'coadd': '61407318',
        'release': 'Y3A2',
    }

    # Submit job
    r = requests.put(
        '{}/job/submit'.format(config['apiBaseUrl']),
        data=data,
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


def submit_query_job():
    """Submits a query job and returns the complete server response which includes the job ID."""

    # Specify API request parameters
    data = {
        'username': config['username'],
        'job': 'query',
        # The database must be either 'dessci' or 'desoper'
        'db': config['database'],
        'filename': 'results.csv',
        'query': '''
            SELECT
            COADD_OBJECT_ID,RA,DEC,
            MAG_AUTO_G G,
            MAG_AUTO_R R,
            WAVG_MAG_PSF_G G_PSF,
            WAVG_MAG_PSF_R R_PSF
            FROM Y3_GOLD_2_2
            WHERE
            RA between 323.36-0.12 and 323.36+0.12 and
            DEC between -0.82-0.12 and -0.82+0.12 and
            WAVG_SPREAD_MODEL_I + 3.0*WAVG_SPREADERR_MODEL_I < 0.005 and
            WAVG_SPREAD_MODEL_I > -1 and
            IMAFLAGS_ISO_G = 0 and
            IMAFLAGS_ISO_R = 0 and
            SEXTRACTOR_FLAGS_G < 4 and
            SEXTRACTOR_FLAGS_R < 4
        '''
    }

    # Submit job
    r = requests.put(
        '{}/job/submit'.format(config['apiBaseUrl']),
        data=data,
        headers={'Authorization': 'Bearer {}'.format(config['auth_token'])}
    )
    response = r.json()
    
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


if __name__ == '__main__':
    # Authenticate and store the auth token for subsequent API calls
    try:
        print('Logging in as user "{}" ("{}") and storing auth token...'.format(config['username'], config['database']))
        login()
    except:
        print('Login failed.')
        sys.exit(1)

    # Submit one query job and one cutout job
    for job_type in ['query', 'cutout']:

        if job_type == 'query':
            print('Submitting query job...')
            response = submit_query_job()
        elif job_type == 'cutout':
            print('Submitting cutout job...')
            response = submit_cutout_job()

        # Store the unique job ID for the new job
        job_id = response['jobid']

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

        # print('Complete job status details:')
        # print(json.dumps(response, indent=2))

        # If successful, display job results
        if job_status == 'success':

            if job_type == 'cutout':
                # Download single compressed archive file containing all job files
                job_archive_filename = '{}.tar.gz'.format(job_id)
                job_archive_file_url = '{}/{}/{}/{}'.format(config['filesBaseUrl'], config['username'], 'cutout', job_archive_filename)
                data = requests.get(job_archive_file_url)
                with open('./{}'.format(job_archive_filename), "wb") as file:
                    file.write(data.content)
                print('Job archive file "{}" downloaded.'.format(job_archive_filename))

            # Construct the job file download URL
            job_url = '{}/{}/{}/{}'.format(config['filesBaseUrl'], config['username'], job_type, job_id)
            download_dir = './{}'.format(job_id)
            # Download each raw job file sequentially to a subfolder of the working directory
            download_job_files(job_url, download_dir)
            print('Files for job "{}" downloaded to "{}"'.format(job_id, download_dir))
        else:
            print('The job "{}" failed.'.format(job_id))
