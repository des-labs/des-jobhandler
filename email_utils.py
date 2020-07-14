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
    def __init__(self, username, recipients, context, char='r', ps=None):
        self.recipients = recipients
        self.server = 'smtp.ncsa.illinois.edu'
        # self.server = 'localhost'
        self.fromemail = 'devnull@ncsa.illinois.edu'
        self.s = smtplib.SMTP(self.server)
        self.msg = MIMEMultipart('alternative')
        self.msg['Subject'] = context['Subject']
        self.msg['From'] = formataddr((str(Header('DESDM Release Team', 'utf-8')), self.fromemail))
        self.msg['To'] = ', '.join(self.recipients)
        self.context = context
        if ps is None:
            self.ps = '''
                <span style="font-size: 11px">
                Trouble opening the link above? Copy and paste the URL directly:
                <br /> {link}
                </span>
                '''.format(link=self.context['link'])
        else:
            self.ps = ps
        self.context['ps'] = self.ps
        self.html = render(os.path.join(os.path.dirname(__file__), 'email_template.html'), self.context)


def send_note(username, jobid, job_name, recipients):
    if not isinstance(recipients, list):
        recipients = [recipients]
    link = '{}/status/{}'.format(envvars.FRONTEND_BASE_URL, jobid)
    context = {
        "Subject": "DESaccess Job Complete: {}".format(job_name),
        "username": username,
        "msg": """
        <p>Your DESaccess job is complete.</p>
        <table width="100%" border="0">
            <tr>
                <td align="left"><b>User<b>:</td>
                <td align="left">{}</td>
            </tr>
            <tr>
                <td align="left"><b>Job name<b>:</td>
                <td align="left" style="font-family: monospace;">{}</td>
            </tr>
            <tr>
                <td align="left"><b>Job ID<b>:</td>
                <td align="left" style="font-family: monospace;">{}</td>
            </tr>
            <tr>
                <td align="left"><b>Status<b>:</td>
                <td align="left">Complete</td>
            </tr>
        </table>
        """.format(username, job_name, jobid),
        "action": "Click Here To View Results",
        "link": link,
    }
    header = SingleEmailHeader(username, recipients, context, char='c')
    MP1 = MIMEText(header.html, 'html')
    header.msg.attach(MP1)
    header.s.sendmail(header.fromemail, header.recipients, header.msg.as_string())
    header.s.quit()
    return "Email Sent to {}".format(header.recipients)


def help_request_notification(username, recipients, jira_issue_number, jira_issue_description):
    if not isinstance(recipients, list):
        recipients = [recipients]
    link = 'https://opensource.ncsa.illinois.edu/jira/browse/{}'.format(jira_issue_number)
    context = {
        "Subject": "New DESaccess Help Request: {}".format(jira_issue_number),
        "username": username,
        "msg": """
        <p>New DESaccess Help Request: {}</p>
        <p>Help request:</p>
        <pre>{}<pre>
        """.format(jira_issue_number, jira_issue_description),
        "action": "Open Jira Issue",
        "link": link,
    }
    header = SingleEmailHeader(username, recipients, context, char='c')
    MP1 = MIMEText(header.html, 'html')
    header.msg.attach(MP1)
    header.s.sendmail(header.fromemail, header.recipients, header.msg.as_string())
    header.s.quit()
    return "Email Sent to {}".format(header.recipients)
