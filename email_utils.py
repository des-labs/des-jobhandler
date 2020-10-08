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
    def __init__(self, username, recipients, context, char='r', template='email_template.html', ps=None):
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
        self.html = render(os.path.join(os.path.dirname(__file__), template), self.context)


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
        "Subject": "DESaccess Help Request: {}".format(jira_issue_number),
        "username": username,
        "msg": """
        <p>DESaccess Help Request: {}</p>
        <p>Help request:</p>
        <pre>{}<pre>
        """.format(jira_issue_number, jira_issue_description),
        "action": "Open Jira Issue",
        "link": link,
    }
    header = SingleEmailHeader(username, recipients, context, char='c')
    MP1 = MIMEText(header.html, 'html')
    header.msg.attach(MP1)
    # The TO and CC header fields are populated by the header construction, and any additional recipient addresses are effectively BCC
    header.s.sendmail(header.fromemail, header.recipients, header.msg.as_string())
    header.s.quit()
    return "Email Sent to {}".format(header.recipients)


def send_activation(firstname, lastname, username, recipients, url):
    if not isinstance(recipients, list):
        recipients = [recipients]
    activate_link = '{}/activate/{}'.format(envvars.FRONTEND_BASE_URL, url)
    context = {
        "Subject": "DESaccess Account Activation Link",
        "username": firstname,
        "msg": """Welcome!<br>
        You need to activate your account
        before accessing DESaccess services. <br > The activation link is valid
        for the next 12 hours""",
        "action": "Click Here To Activate Your Account",
        "link": activate_link,
    }
    header = SingleEmailHeader(username, recipients, context, char='c')
    MP1 = MIMEText(header.html, 'html')
    header.msg.attach(MP1)
    # The TO and CC header fields are populated by the header construction, and any additional recipient addresses are effectively BCC
    header.s.sendmail(header.fromemail, header.recipients, header.msg.as_string())
    header.s.quit()
    return "Email Sent to {}".format(header.recipients)


def send_reset(username, recipients, token):
    if not isinstance(recipients, list):
        recipients = [recipients]
    link = '{}/reset/{}'.format(envvars.FRONTEND_BASE_URL, token)
    context = {
        "Subject": "DESaccess Account Password Reset Link",
        "username": username,
        "msg": """
        <p>Someone (hopefully you) requested a password reset for your DESaccess account. Click the link below to reset your password.<p>
        <p>If you did not request a password reset, you may ignore this message.</p>
        <p>The activation link is valid for the next 24 hours</p>
        """,
        "action": "Reset your password",
        "link": link,
    }
    header = SingleEmailHeader(username, recipients, context, char='c')
    MP1 = MIMEText(header.html, 'html')
    header.msg.attach(MP1)
    # The TO and CC header fields are populated by the header construction, and any additional recipient addresses are effectively BCC
    header.s.sendmail(header.fromemail, header.recipients, header.msg.as_string())
    header.s.quit()
    return "Email Sent to {}".format(header.recipients)


def email_notify_admins_new_user(firstname, lastname, username, recipients, url):
    if not isinstance(recipients, list):
        recipients = [recipients]
    activate_link = '{}'.format(url)
    context = {
        "Subject": "New DESaccess user: {}".format(username),
        "username": username,
        "msg": """
        <p>A new DESaccess user was successfully registered:</p>
        <pre>
        Username: {}
        Given Name: {}
        Family Name: {}
        <pre>
        """.format(username, firstname, lastname),
        "action": "Activation Link",
        "link": activate_link,
    }
    header = SingleEmailHeader(username, recipients, context, char='c')
    MP1 = MIMEText(header.html, 'html')
    header.msg.attach(MP1)
    # The TO and CC header fields are populated by the header construction, and any additional recipient addresses are effectively BCC
    header.s.sendmail(header.fromemail, header.recipients, header.msg.as_string())
    header.s.quit()
    return "Email Sent to {}".format(header.recipients)


def send_job_prune_warning(username, recipients, job_name, job_id, warning_period, job_lifetime, renewals_remaining, renewal_token, expiration_date):
    if not isinstance(recipients, list):
        recipients = [recipients]
    link = '{}/renew/{}'.format(envvars.FRONTEND_BASE_URL, renewal_token)
    opt_out_link = 'https://{}{}/user/preference/stoprenewalemails?token={}'.format(envvars.BASE_DOMAIN, envvars.BASE_PATH, renewal_token)
    if renewals_remaining <= 1:
        renewal_message = '<b>This is the last time you may renew your job file storage.</b>'
    else:
        renewal_message = 'You have {} renewals remaining.'.format(renewals_remaining-1)
    context = {
        "Subject": "DESaccess Job Scheduled for Deletion",
        "username": username,
        "msg": """
        <p>The file storage for job <code>{job_name}</code> (Job ID: <code>{job_id}</code>) is scheduled for automatic deletion on {expiration_date} (UTC).<p>
        <p>You may use the link below to extend your job file storage another {job_lifetime} days. {renewal_message}</p>
        <p>To disable future renewal emails (for all jobs), <a href="{opt_out_link}">open this link</a>.</p>
        """.format(
            job_name=job_name,
            job_id=job_id,
            warning_period=warning_period,
            renewal_message=renewal_message,
            job_lifetime=job_lifetime,
            expiration_date=expiration_date,
            opt_out_link=opt_out_link),
        "action": "Renew job file storage",
        "link": link,
    }
    header = SingleEmailHeader(username, recipients, context, char='c')
    MP1 = MIMEText(header.html, 'html')
    header.msg.attach(MP1)
    # The TO and CC header fields are populated by the header construction, and any additional recipient addresses are effectively BCC
    header.s.sendmail(header.fromemail, header.recipients, header.msg.as_string())
    header.s.quit()
    return "Email Sent to {}".format(header.recipients)


def email_notify_public_list(recipients, subject, body):
    if not isinstance(recipients, list):
        recipients = [recipients]
    context = {
        "Subject": subject,
        "msg": body,
        "link": ''
    }
    header = SingleEmailHeader('', recipients, context, char='c', template='email_template_public_notification.html', ps='')
    MP1 = MIMEText(header.html, 'html')
    header.msg.attach(MP1)
    # The TO and CC header fields are populated by the header construction, and any additional recipient addresses are effectively BCC
    header.s.sendmail(header.fromemail, header.recipients, header.msg.as_string())
    header.s.quit()
    return "Email Sent to {}".format(header.recipients)

# def parse_email_list_file():
#     # logger.setLevel(logging.WARNING)
#     with open('/email_list/desaccess_email_list.txt', 'r') as listfile:
#         all_lines = listfile.readlines()
#         email_list = []
#         for line in all_lines:
#             line = line.strip()
#             # logger.info('Parsing line: "{}"'.format(line))
#             try:
#                 user_info = []
#                 for item in re.sub(r'[\s]+', ',', line.strip()).split(','):
#                     # logger.info('    Item: "{}"'.format(item))
#                     # If a comment is encountered, skip any remaining items
#                     if re.match(r'^#.*', item):
#                         break
#                     elif item != '':
#                         user_info.append(item)
#                 # Simplistic check that the first item is an email address
#                 if len(user_info) >= 3 and user_info[0].find('@') >= 0 and user_info[0].find('.') >= 0:
#                     email = user_info[0]
#                     given_name = user_info[1]
#                     family_name = ' '.join(user_info[2:])
#                     email_list.append([email, given_name, family_name])
#                     # logger.info('    User info parsed: {}/{}/{}'.format(email, given_name, family_name))
#                     if len(user_info) > 3:
#                         logger.info('    User info parsed: ({}) {}    {}'.format(email, given_name, family_name))
#                 # Ignore empty values due to comment lines
#                 elif user_info:
#                     logger.error('Invalid user info: {}'.format(user_info))
#             except Exception as e:
#                 logger.error('Error parsing email list line: {}'.format(str(e).strip()))
#         logger.info('Total user accounts in email address: {}'.format(len(email_list)))
