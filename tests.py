import os
import yaml
import main

def run_concurrency_tests():
    with open(os.path.join(os.path.dirname(__file__), 'concurrency-test.yaml')) as cfile:
        tests = yaml.safe_load(cfile)
        for job in tests['jobs']:
            #delay = job[0]
            duration = job[1]
            quantity = int(job[2])
            for run in range(quantity):
                main.submit_test(
                    {
                        "username": "tester",
                        "time": duration,
                        "job": "test"
                    }
                )
