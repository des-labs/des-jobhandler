#!/bin/python3

import os
import sys
import glob
from datetime import datetime
import time
from shutil import rmtree
import logging

'''
This script is a standalone utility script for DESaccess admins to use to 
perform garbage collection on expired cutout and query jobs that have been
missed by the periodic webcron script for whatever reason. It scans the 
two job storage directories for job output folder older than a certain age
and deletes the folder if the `--delete` command line option is invoked;
otherwise it only prints a message displaying the age and size of the job
directory.
'''


## Configure logging
timestamp = datetime.strftime(datetime.utcnow(), '%Y%m%d%H%M%S')
logging.basicConfig(
    filename=f'/var/tmp/desaccess_prune_jobs.{timestamp}.log',
    format='%(asctime)s : %(levelname)s : %(message)s',
    level=logging.DEBUG
)

def get_size(start_path='.'):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size


def main(option='', task_root_dirs=[]):
    for task_root_dir in task_root_dirs:
        # Expiration is 14 days with two optional renewals. Pad with another week to be safe.
        days_old = 14 * 3 + 7
        os.chdir(task_root_dir)
        reclaimed_space = 0
        for job_path in glob.iglob('*/*/*'):
            if not os.path.isdir(job_path):
                continue
            parent_dir = os.path.split(job_path)[0]
            job_type = os.path.split(parent_dir)[1]
            if not job_type in ['cutout', 'query']:
                continue
            job_mod_time = round(os.stat(job_path).st_mtime)
            oldest_time = time.time() - (days_old * 24 * 60 * 60)
            # Time in days since last modification of file
            days_ago = round((time.time() - job_mod_time) / (24 * 60 * 60))
            if job_mod_time - oldest_time > 0:
                continue
            job_size = get_size(job_path)
            reclaimed_space += job_size
            msg = f'''Deleting job "{job_path}" modified {days_ago} days ago ({round(1.0*job_size/1024.0**2)} MiB / Total space reclaimed: {round(1.0*reclaimed_space/1024.0**3)} GiB)...'''
            if option == '--delete':
                logging.info(msg)
                rmtree(job_path)
            else:
                logging.info(f'''[dry run] {msg}''')
        logging.info(f'''Total space reclaimed from "{task_root_dir}": {round(1.0*reclaimed_space/1024.0**3)} GiB''')


if __name__ == "__main__":
    try:
        option = sys.argv[1]
    except:
        option = ''
    task_root_dirs = [
        '/des004/deslabs/cluster-prod/namespaces/default/deslabs-legacy/tasks',
        '/des004/deslabs/cluster-prod/namespaces/deslabs/deslabs-legacy/tasks',
    ]
    main(option=option, task_root_dirs=task_root_dirs)
