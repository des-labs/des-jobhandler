#!/usr/bin/env python3

import os
import sys
import requests
import time
import json

try:
    username = os.environ['CRONJOB_USER']
    password = os.environ['CRONJOB_PASS']
    base_url = os.environ['CRONJOB_BASEURL']
    db = os.environ['CRONJOB_DB']

    # Import credentials and config from environment variables
    config = {
        'auth_token': '',
        'apiBaseUrl': '{}/desaccess/api'.format(base_url),
        'filesBaseUrl': '{}/files-desaccess/'.format(base_url),
        'username': username,
        'password': password,
        'database': db,
    }
except:
    sys.exit(1)


def login():
    """Obtains an auth token using the username and password credentials for a given database.
    """
    # Login to obtain an auth token
    r = requests.request( 'POST',
        '{}/login'.format(config['apiBaseUrl']),
        data={
            'username': config['username'],
            'password': config['password'],
            'database': config['database']
        },
        # verify=False
    )
    # Store the JWT auth token
    config['auth_token'] = r.json()['token']
    return config['auth_token']


def trigger_cronjob(cronjob):
    """Submits a query job and returns the complete server response which includes the job ID."""

    # Specify API request parameters
    params = {
        'cronjob': cronjob,
    }

    # Submit job
    response = requests.request( 'POST',
        '{}/dev/webcron'.format(config['apiBaseUrl']),
        params=params,
        headers={'Authorization': 'Bearer {}'.format(config['auth_token'])},
        # verify=False
    )
    try:
        response = response.json()
        print(json.dumps(response, indent=2))
    except:
        print(response.text)
    
    return response


if __name__ == '__main__':
    # Authenticate and store the auth token for subsequent API calls
    try:
        print('Logging in as user "{}" ("{}") and storing auth token...'.format(config['username'], config['database']))
        login()
    except:
        print('Login failed.')
        sys.exit(1)

    response = trigger_cronjob('refresh_database_table_cache')
