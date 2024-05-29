import sys
import requests
import json
import smtplib
import socket
import argparse
import os
import ssl
from ssl import Purpose
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import date
from datetime import timedelta

########################################################################
# Config options
#
APP_PROFILE_NAME = "" #<--- Application name as it appears in Veracode
API_BASE = "https://api.veracode.com/appsec/"
HEADERS = {"User-Agent": "Weekly Flaw Checking"}

#email the report is coming from
SENDER_EMAIL = 'example.user@email.com'

# Email list for team (comma separated list)
RECEIVER_EMAIL = 'example.user1@email.com,example.user2@email.com,example.user3@email.com'
# SMTP server address 
SERVER = 'smtp.domain-example.com'
PEROID = 'Weekly'
#branch or tag
BRANCH = ''
MESSAGE = ''
notMitigatedNum = 0
#
#
########################################################################


parser = argparse.ArgumentParser(description='argument parser test')
parser.add_argument("--rec", default=RECEIVER_EMAIL, help='mail addresses of the report recievers')
parser.add_argument("--server", default=SERVER, help='the smtp server address')
parser.add_argument("--freq", default=PEROID, help='period of sending reports')
parser.add_argument("--branch", default=BRANCH, help='branch for he veracode scan')
parser.add_argument("--msg", default=MESSAGE, help='error message for veracode scan')
args = parser.parse_args()

smtp_server = args.server
frep = args.freq
branch = args.branch
msg = args.msg

print("receiver is {}".format(args.rec))
print("smtp server is {}".format(smtp_server))
print("period is {}".format(frep))
print("branch is {}".format(branch))
print("smtp server is {}".format(smtp_server))
print("msg is {}".format(msg))

SUBJECT = 'Veracode Flaw ' + frep + ' Report based on ' +  branch
MAILTEMPSTART = """
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <style type="text/css">
      table {
        background: white;
        border-radius:3px;
        border-collapse: collapse;
        height: auto;
        max-width: 2000px;
        padding:5px;
        width: 100%;
        animation: float 5s infinite;
      }
      th {
        color:#D5DDE5;;
        background:#5793fa;
        border-bottom: 3px solid #9ea7af;
        font-size:14px;
        font-weight: 300;
        padding:10px;
        text-align:center;
        vertical-align:middle;
      }
      tr {
        border-top: 1px solid #C1C3D1;
        border-bottom: 1px solid #C1C3D1;
        border-left: 1px solid #C1C3D1;
        color:#000000;
        font-size:14px;
        font-weight:normal;
      }
      tr:hover td {
        background:#4E5066;
        color:#FFFFFF;
        border-top: 1px solid #22262e;
      }
      td {
        background:#FFFFFF;
        padding:10px;
        text-align:left;
        vertical-align:middle;
        font-weight:300;
        font-size:14px;
        border-right: 1px solid #C1C3D1;
      }
    </style>
  </head>
  <body>
    Hi All,<br><br>
"""
MAILTEMPMIDDLE="""
    This is an auto generated report for Veracode application scan Status.<br>
    The last update time of the application scan is <span style='color: red'>{}</span>.<br>
    The number of remaining flaws not mitigated is <span style='color: red'>{}</span>.<br>
    The following is the {APP_PROFILE_NAME} Veracode flaw list that is violating the policy.<br>
    Please pay attention to the <span style='color: red'>red marked lines</span>. Their grace periods expire in less 30 days.<br><br>
    <table>
      <thead>
        <tr style="border: 1px solid #1b1e24;">
          <th>Scan Type</th>
          <th>Issue ID</th>
          <th>Severity</th>
          <th>Issue Type</th>
          <th>Attack Vector</th>
          <th>Module</th>
          <th>Location</th>
          <th>Resolution Status</th>
          <th>Grace Period Expires Date</th>
        </tr>
      </thead>
      <tbody>
"""
MAILTEMPMIDDLEWITHERROR="""
    This is an auto generated report for Veracode application scan Status.<br>
    I am sorry, there is something wrong with the Veracode scan.<br>
    The detail error is :<br><span style='color: red'>{}</span>.<br>
    <br><br>
    <table>
      <tbody>
"""
MAILTEMPEND = """
      </tbody>
    </table>
    <br>
  </body>
</html>
"""

def callVeracodeAPI(url):
    try:
        api_base = "https://api.veracode.com/appsec/v1"
        headers = {"User-Agent": "Python HMAC Example"}
        #response = requests.get(api_base + "/applications", auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)
        response = requests.get(url, auth = RequestsAuthPluginVeracodeHMAC(), headers = HEADERS)
    except requests.RequestException as e:
        print("Failed in API call to {}.".format(url))
        print(e)
        sys.exit(1)
    if response.ok:
        return response.json()
    else:
        print("Failed in API call to {}. Got return code {}.".format(url, response.status_code))
        sys.exit(1)

def getAppGuid():
    appData = callVeracodeAPI(API_BASE + "v1/applications")
    for app in appData["_embedded"]["applications"]:
        if app["profile"]["name"] == APP_PROFILE_NAME:
            return app["guid"]

def extractFindingPrimaryKeys(fList, rawList):
    global notMitigatedNum
    for finding in rawList:
        pkeys = dict()
        if finding["finding_status"]["resolution_status"] != "APPROVED":
            notMitigatedNum = notMitigatedNum + 1
            pkeys["resolution_status"] = finding["finding_status"]["resolution_status"]
            pkeys["scan_type"] = finding["scan_type"]
            pkeys["issue_id"] = finding["issue_id"]
            severity = finding["finding_details"]["severity"]
            if severity == 0:
                severityStr = "Informational"
            elif severity == 1:
                severityStr = "Very Low"
            elif severity == 2:
                severityStr = "Low"
            elif severity == 3:
                severityStr = "Medium"
            elif severity == 4:
                severityStr = "High"
            elif severity == 5:
                severityStr = "Very High"
            pkeys["severity"] = severityStr
            pkeys["issue_type"] = finding["finding_details"]["finding_category"]["name"] + " - " + finding["finding_details"]["cwe"]["name"]
            pkeys["grace_period"] = finding["grace_period_expires_date"]
            if pkeys["scan_type"] == "MANUAL":
                pkeys["attack_vector"] = finding["finding_details"]["input_vector"]
                pkeys["module"] = finding["finding_details"]["module"]
                pkeys["location"] = finding["finding_details"]["location"]
            elif pkeys["scan_type"] == "DYNAMIC":
                pkeys["attack_vector"] = finding["finding_details"]["attack_vector"]
                pkeys["module"] = ""
                pkeys["location"] = finding["finding_details"]["url"]
            else:
                pkeys["attack_vector"] = finding["finding_details"]["attack_vector"]
                pkeys["module"] = finding["finding_details"]["module"]
                pkeys["location"] = finding["finding_details"]["file_path"] + ":{}".format(finding["finding_details"]["file_line_number"])
            fList.append(pkeys)

def getFindingList(guid):
    url = API_BASE + "v2/applications/" + guid + "/findings?include_exp_date=true&violates_policy=true&size=50"
    fList = []    
    fData = callVeracodeAPI(url)
    totalPages = fData["page"]["total_pages"]
    extractFindingPrimaryKeys(fList, fData["_embedded"]["findings"])
        
    for p in range(1, totalPages):
        fData = callVeracodeAPI(url + "&page={}".format(p))
        extractFindingPrimaryKeys(fList, fData["_embedded"]["findings"])
            
    return fList

def updateMailStart(guid):
    print("### notMitigatedNum is {}.".format(notMitigatedNum))
    summary = callVeracodeAPI(API_BASE + "v2/applications/" + guid + "/summary_report")
    return MAILTEMPSTART + MAILTEMPMIDDLE.format(summary["last_update_time"], notMitigatedNum)

def get_server(smarthost):
    ssl_setting = os.getenv('SSL', None)
    if ssl_setting is not None:
        if ssl_setting == 'SSL':
            print('SSL CONNECT')
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            server = smtplib.SMTP_SSL(smarthost, port=465, context=ctx)
        elif ssl_setting == 'TLS':
            print('TLS CONNECT')
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            server = smtplib.SMTP(smarthost)
            print('TLS START')
            server.starttls(context=ctx)
        else:
            print('SMTP PLAIN WITH DEFAULTED SSL PARAM')
            server = smtplib.SMTP(smarthost)
    else:
        print('PLAIN SMTP')
        server = smtplib.SMTP(smarthost, port=587)
    return server

def sendMail(fList, mailStart):
    error = 0
    today = date.today()
    timeout = timedelta(days=30)
    html = mailStart
    for flaw in fList:
        expdate = date(int(flaw["grace_period"][0:4]), int(flaw["grace_period"][5:7]), int(flaw["grace_period"][8:10]))
        if expdate - today < timeout:
            style = " style='color: red'"
        else:
            style = ""
        line = """
<tr{0}>
  <td>{1[scan_type]}</td>
  <td>{1[issue_id]:d}</td>
  <td>{1[severity]}</td>
  <td>{1[issue_type]}</td>
  <td>{1[attack_vector]}</td>
  <td>{1[module]}</td>
  <td>{1[location]}</td>
  <td>{1[resolution_status]}</td>
  <td>{1[grace_period]}</td>
</tr>
""".format(style, flaw)
        html += line
    html += MAILTEMPEND

    recipients = args.rec.split(',')

    message = MIMEMultipart("alternative", None, [MIMEText(html, 'html')])
    message['Subject'] = SUBJECT
    message['From'] = SENDER_EMAIL
    #message['To'] = args.rec
    for receiver in recipients:
        print("receiver is {}.".format(receiver))
        message['To'] = receiver
    #message['To'] = args.rec
    
    smarthost = smtp_server
    server = None
    
    print("The email content is {}.".format(message.as_string()))
    
    try:
        #ipresolv = socket.gethostbyname_ex(smarthost)
        #print("The IP Address of the Domain Name is {}.".format(repr(ipresolv)))
        server = get_server(smarthost)
        server.set_debuglevel(1)
        server.sendmail(SENDER_EMAIL, recipients, message.as_string())
    except Exception as err:
        print('Failed to send email through smtp.')
        print(err)
        error = 1
    else:
        print('Email sent!')
    finally:
        if server is not None:
            server.quit()
        if error == 1:
            sys.exit(1)
    
def sendMailWithErr():
    # Split the error message by '|' and format it.
    # [21.12.22 04:18:17] * Action "UploadAndScan" returned the following message:|
    # [21.12.22 04:18:17] * App not in state where new builds are allowed.|
    # [21.12.22 04:18:17]|
    # [21.12.22 04:18:18]|
    # [21.12.22 04:18:18] * A scan is in progress or has failed to complete successfully. Wait for the current scan to complete or delete the failed scan from the Veracode Platform and try again.
    error = 0
    list_message = msg.split('|')
    new_msg = '<br>'.join(list_message)
    html = MAILTEMPSTART + MAILTEMPMIDDLEWITHERROR.format(new_msg)
    html += MAILTEMPEND
    
    message = MIMEMultipart("alternative", None, [MIMEText(html, 'html')])
    message['Subject'] = SUBJECT
    message['From'] = SENDER_EMAIL
    message['To'] = args.rec
    
    smarthost = smtp_server
    server = None
    
    print("The error message is {}".format(message.as_string()))
    
    try:
        ipresolv = socket.gethostbyname_ex(smarthost)
        print("The IP Address of the Domain Name is {}.".format(repr(ipresolv)))
        server = get_server(smarthost)
        server.set_debuglevel(1)
        server.sendmail(RECEIVER_EMAIL, args.rec.split(","), message.as_string())
    except Exception as err:
        print('Failed to send email through smtp.')
        print(err)
        error = 1
    else:
        print('Email sent!')
    finally:
        if server is not None:
            server.quit()
        if error == 1:
            sys.exit(1)
    
if __name__ == '__main__':
    if(len(msg) == 0):
        appGuid = getAppGuid()
        findingList = getFindingList(appGuid)
        mailStart = updateMailStart(appGuid)
        sendMail(findingList, mailStart)
    else:
        sendMailWithErr()
