import tornado.ioloop
import tornado.web
import tornado
import json
# from kubernetes import client, config
# config.load_kube_config(config_file='k8s.conf')

class BaseHandler(tornado.web.RequestHandler):

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Content-Type")
        self.set_header('Access-Control-Allow-Methods', ' POST, PUT, DELETE, OPTIONS')

    def options(self):
        self.set_status(204)
        self.finish()

class MainHandler(BaseHandler):
    def post(self):
        name = self.get_argument('name','')
        data_json = tornado.escape.json_decode(self.request.body)
        name = data_json['name']
        print(name)

        out = dict(msg='Job submitted by {}'.format(name))
        self.write(json.dumps(out,indent=4))


## This is the one providing a list of hidden/allowed resources
class InitHandler(BaseHandler):
    def post(self):
        username = self.get_argument('username','')
        data_json = tornado.escape.json_decode(self.request.body)
        username = data_json['username']
        print(username)
        out = dict(hidden=['page3'])
        self.write(json.dumps(out,indent=4))



def make_app():
    return tornado.web.Application([
        (r"/test/?", MainHandler),
        (r"/init/?", InitHandler),
    ],debug=True)

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
