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



if __name__ == '__main__':
    # Authenticate and store the auth token for subsequent API calls
    try:
        print('Logging in as user "{}" ("{}") and storing auth token...'.format(config['username'], config['database']))
        login()
    except:
        print('Login failed.')
        sys.exit(1)

    # r = requests.post(
    #     f'''{config['apiBaseUrl']}/profile/update/info''',
    #     data={
    #         'username': 'user1234',
    #         'firstname': 'Jane',
    #         'lastname': 'Doe',
    #         'email': 'doe@example.com',
    #     },
    #     headers={'Authorization': 'Bearer {}'.format(config['auth_token'])}
    # )
    # response = r.json()
    # # Refresh auth token
    # config['auth_token'] = response['new_token']
    # print(json.dumps(response, indent=2))
