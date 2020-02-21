import tornado.ioloop
import tornado.web
import tornado.wsgi
import tornado
import json
import jwt
import datetime
import sqlite3
import logging
import uuid
import kubejob
import os
SECRET = 'my_secret_key'

log_format = "%(asctime)s  %(name)8s  %(levelname)5s  %(message)s"
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.FileHandler("test.log"), logging.StreamHandler()],
    format=log_format,
)
logger = logging.getLogger("main")


def get_jobid():
    return str(uuid.uuid4()).replace("-", "")

def register_job(username, job, jobid):
    conn = sqlite3.connect("deslabs.db")
    c = conn.cursor()
    t = tuple([username, job, jobid, "PENDING"])
    c.execute("INSERT INTO Jobs VALUES {0}".format(t))
    conn.commit()
    conn.close()

def submit_test(body):
    username = body["username"].lower()
    time = int(body["time"])
    job = body["job"]
    jobid = get_jobid()
    conf = {"job": job}
    conf["namespace"] = "default"
    conf["cm_name"] = "{}-{}-{}-cm".format(conf["job"], jobid, username)
    conf["job_name"] = "{}-{}-{}".format(conf["job"], jobid, username)
    # conf["image"] = "mgckind/test-task:1.3"
    conf["image"] = os.environ['DOCKER_IMAGE']
    conf["command"] = ["python", "test.py"]
    conf["configjob"] = {
        "name": conf["job"],
        "jobid": jobid,
        "username": username,
        "inputs": {"time": time},
        "outputs": {"log": "{}.log".format(conf["job"])},
    }
    kubejob.create_configmap(conf)
    kubejob.create_job(conf)
    msg = "Job:{} id:{} by:{}".format(conf["job"], jobid, username)
    register_job(username, job, jobid)
    return msg

class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Content-Type")
        self.set_header("Access-Control-Allow-Methods", " POST, PUT, DELETE, OPTIONS")

    def options(self):
        self.set_status(204)
        self.finish()

    def getarg(self, arg, default=""):
        temp = self.get_argument(arg, default)
        try:
            data_json = tornado.escape.json_decode(self.request.body)
            temp = default
            temp = data_json[arg]
        except:
            pass
        return temp

class ProfileHandler(BaseHandler):
    def post(self):
        body = { k: self.get_argument(k) for k in self.request.arguments }
        token = body["token"]
        decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
        exptime =  datetime.datetime.utcfromtimestamp(decoded['exp'])
        ttl = (exptime - datetime.datetime.utcnow()).seconds
        logger.info(ttl)
        response = {'username': decoded["username"], "email": decoded["email"], "ttl": ttl}
        logger.info(response)
        self.write(response)



class LoginHandler(BaseHandler):

    def post(self):
        body = { k: self.get_argument(k) for k in self.request.arguments }
        username = body["username"]
        #passwd = body["password"]
        email = "{}@test.test".format(username)
        encoded = jwt.encode({
            'username' : username,
            'email' : email,
            'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=600)},
            SECRET,
            algorithm='HS256'
        )
        response = {'username': username, 'email':email, 'token': encoded.decode(encoding='UTF-8')}
        self.write(json.dumps(response))


class JobHandler(BaseHandler):
    def put(self):
        body = { k: self.get_argument(k) for k in self.request.arguments }
        logger.debug(body)
        job = body["job"]
        if job == "test":
           msg = submit_test(body)
           logger.info(msg)
        else:
            msg = 'Job {} not defined'.format(job)
        out = dict(msg=msg)
        self.write(json.dumps(out, indent=4))


    def delete(self):
        username = self.getarg("username")
        job = self.getarg("job")
        jobid = self.getarg("jobid")
        conf = {"job": job}
        conf["namespace"] = "default"
        conf["job_name"] = "{}-{}-{}".format(conf["job"], jobid, username)
        conf["cm_name"] = "{}-{}-{}-cm".format(conf["job"], jobid, username)
        kubejob.delete_job(conf)
        out = dict(msg="done")
        self.write(json.dumps(out, indent=4))

    def post(self):
        username = self.getarg("username")
        job = self.getarg("job")
        jobid = self.getarg("jobid")
        conf = {"job": job}
        conf["namespace"] = "default"
        conf["job_name"] = "{}-{}-{}".format(conf["job"], jobid, username)
        status = kubejob.status_job(conf)
        out = dict(
            msg="done",
            avtive=status.active,
            succeeded=status.succeeded,
            failed=status.failed,
        )
        self.write(json.dumps(out, indent=4))



## This is the one providing a list of hidden/allowed resources
class InitHandler(BaseHandler):
    def post(self):
        username = self.getarg("username")
        logger.debug(username)
        conn = sqlite3.connect("deslabs.db")
        c = conn.cursor()
        t = c.execute("select pages from access where username = '{}'".format(username))
        d = t.fetchone()
        conn.close()
        pages = []
        if d is not None:
            pages = d[0].replace(" ", "").split(",")
        out = dict(access=pages)
        self.write(json.dumps(out, indent=4))


def make_app(basePath = ''):
    settings = {"debug": False}
    return tornado.web.Application(
        [
            (r"{}/job/status?".format(basePath), JobHandler),
            (r"{}/job/delete?".format(basePath), JobHandler),
            (r"{}/job/submit?".format(basePath), JobHandler),
            (r"{}/login/?".format(basePath), LoginHandler),
            (r"{}/profile/?".format(basePath), ProfileHandler),
            (r"{}/init/?".format(basePath), InitHandler),
        ],
        **settings
    )

if __name__ == "__main__":

    if int(os.environ['SERVICE_PORT']):
        servicePort = int(os.environ['SERVICE_PORT'])
    else:
        servicePort = 8080
    if os.environ['BASE_PATH'] == '' or os.environ['BASE_PATH'] == '/' or not isinstance(os.environ['BASE_PATH'], str) :
        basePath = ''
    else:
        basePath = os.environ['BASE_PATH']

    app = make_app(basePath = basePath)
    app.listen(servicePort)
    tornado.ioloop.IOLoop.current().start()
