import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
import jinja2
import os
import envvars

def render(tpl_path, context):
    path, filename = os.path.split(tpl_path)
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(path or './')
    ).get_template(filename).render(context)

class SingleEmailHeader(object):
    def __init__(self, username, toemail, context, char='r', ps=None):
        self.toemail = toemail
        self.server = 'smtp.ncsa.illinois.edu'
        # self.server = 'localhost'
        self.fromemail = 'devnull@ncsa.illinois.edu'
        self.s = smtplib.SMTP(self.server)
        self.msg = MIMEMultipart('alternative')
        self.msg['Subject'] = context['Subject']
        self.msg['From'] = formataddr((str(Header('DESDM Release Team', 'utf-8')), self.fromemail))
        self.msg['To'] = self.toemail
        self.context = context
        if ps is None:
            self.ps = 'PS: This is the full link you can copy/paste into the browser:<br /> <span style="font-size: 11px">{link}</span>'.format(link=self.context['link'])
        else:
            self.ps = ps
        self.context['ps'] = self.ps
        self.html = render(os.path.join(os.path.dirname(__file__), 'template.html'), self.context)


def send_note(username, jobid, toemail):
    bcc = 'mgckind@gmail.com'
    link = envvars.API_BASE_URL
    context = {
        "Subject": "Job {} is completed".format(jobid),
        "username": username,
        "msg": """The job <b>{}</b> was completed. <br>
        The results can be retrieved from the link below""".format(jobid),
        "action": "Click Here To See Your Jobs",
        "link": link,
    }
    header = SingleEmailHeader(username, toemail, context, char='c')
    MP1 = MIMEText(header.html, 'html')
    header.msg.attach(MP1)
    header.s.sendmail(header.fromemail, [header.toemail, bcc], header.msg.as_string())
    header.s.quit()
    return "Email Sent to %s" % header.toemail
