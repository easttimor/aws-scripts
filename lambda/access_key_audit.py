###############################################################################
# Name:
#       Audit Access Key Age
# Purpose:
#       Reads the credential report
#       Determines the age of each access key
#       Builds a report of all keys older than KEY_AGE_WARNING
#       Takes action (inactive/delete) on non-compliant Access Keys
# Permissions:
#       iam:GetCredentialReport
#       iam:GetAccessKeyLastUsed
#       iam:ListAccessKeys
#       iam:ListGroupsForUser
#       ses:SendEmail
#       ses:SendRawEmail
# Environment Variables:
#       ACCOUNT_NAME: AWS Account (friendly) Name
#       ACCOUNT_NUMBER: AWS Account Number
#       ARMED: Set to "true" to take action on keys; "false" limits to reporting
#       LOG_LEVEL: (optional): sets the level for function logging
#                  valid input: critical, error, warning, info (default), debug
#       EMAIL_ENABLED: used to enable or disable the SES emailed report
#       EMAIL_SOURCE: send from address for the email, authorized in SES
#       EMAIL_SUBJECT: subject line for the email
#       EMAIL_TARGET: default email address if event fails to pass a valid one
#       EXEMPT_GROUP: IAM Group that is exempt from actions on access keys
#       KEY_AGE_DELETE: age at which a key should be deleted (e.g. 120)
#       KEY_AGE_INACTIVE: age at which a key should be inactive (e.g. 90)
#       KEY_AGE_WARNING: age at which to warn (e.g. 75)
#       KEY_USE_THRESHOLD: age at which unused keys should be deleted (e.g.30)
#       S3_ENABLED: set to "true" and provide S3_BUCKET if the audit report
#                   should be written to S3
#       S3_BUCKET: bucket name to write the audit report to if S3_ENABLED is
#                   set to "true"
###############################################################################

from botocore.exceptions import ClientError
from time import sleep
import boto3
import collections
import csv
import datetime
import dateutil
import io
import json
import logging
import os
import re


###############################################################################
# Standard logging config
###############################################################################
DEFAULT_LOG_LEVEL = logging.INFO
LOG_LEVELS = collections.defaultdict(
    lambda: DEFAULT_LOG_LEVEL,
    {
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG
    }
)

# Lambda initializes a root logger that needs to be removed in order to set a
# different logging config
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)

logging.basicConfig(
    format='%(asctime)s.%(msecs)03dZ [%(name)s][%(levelname)-5s]: %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    level=LOG_LEVELS[os.environ.get('LOG_LEVEL', '').lower()])

log = logging.getLogger(__name__)


###############################################################################
# HANDLER
###############################################################################
def lambda_handler(event, context):
    client_iam = boto3.client('iam')

    # Generate Credential Report
    generate_credential_report(client_iam)

    # Get Credential Report
    report_counter = 0
    report = get_credential_report(client_iam, report_counter)

    # Process Users in Credential Report
    if report is not None:
        body = process_users(client_iam, report)

    # Process message for SES
    process_message(body)


###############################################################################
# Process each user and key in the Credential Report
###############################################################################
def process_users(client_iam, report):
    # Initialize message content
    htmlBody = ''

    # Access the credential report and process it
    for row in report:
        # A row is a unique IAM user
        UserName = row['user']
        log.debug("Processing user: %s", UserName)
        exemption = 'false'
        if UserName != '<root_account>':

            # Test group exemption
            groups = client_iam.list_groups_for_user(UserName=UserName)
            for g in groups['Groups']:
                if g['GroupName'] == os.environ['EXEMPT_GROUP']:
                    exemption = 'true'
                    log.info('User is exempt via group membership in: %s', g['GroupName'])

            # Process Access Keys for user
            access_keys = client_iam.list_access_keys(UserName=UserName)
            for key in access_keys['AccessKeyMetadata']:
                key_age = object_age(key['CreateDate'])

                if key_age >= int(os.environ['KEY_AGE_WARNING']):
                    # reset
                    report = 'true'
                    AccessKeyId = key['AccessKeyId']

                    # gather full info about the key
                    GetKey = client_iam.get_access_key_last_used(
                        AccessKeyId=AccessKeyId
                    )

                    # LastUsedDate value will not exist if key not used
                    if 'LastUsedDate' in GetKey['AccessKeyLastUsed']:
                        LastUsedDate = GetKey['AccessKeyLastUsed']['LastUsedDate']
                    else:
                        LastUsedDate = 'Unused'

                    if LastUsedDate == 'Unused' and key_age >= int(os.environ['KEY_USE_THRESHOLD']) and exemption == 'false':
                        # Delete unused keys
                        delete_access_key(AccessKeyId, UserName, client_iam)
                        line = '<tr bgcolor= "#E6B0AA"><td>'+UserName+'</td><td>'+key['AccessKeyId']+'</td><td>'+str(key_age)+'</td><td>'+'DELETED'+'</td><td>'+str(LastUsedDate)+'</td></tr>'
                    elif key_age >= int(os.environ['KEY_AGE_DELETE']) and exemption == 'false':
                        # Delete key exceeding age of KEY_AGE_DELETE
                        delete_access_key(AccessKeyId, UserName, client_iam)
                        line = '<tr bgcolor= "#E6B0AA"><td>'+UserName+'</td><td>'+key['AccessKeyId']+'</td><td>'+str(key_age)+'</td><td>'+'DELETED'+'</td><td>'+str(LastUsedDate)+'</td></tr>'
                    elif key_age >= int(os.environ['KEY_AGE_INACTIVE']) and exemption == 'false':
                        # Disable key exceeding age of KEY_AGE_INACTIVE
                        disable_access_key(AccessKeyId, UserName, client_iam)
                        line = '<tr bgcolor= "#F4D03F"><td>'+UserName+'</td><td>'+key['AccessKeyId']+'</td><td>'+str(key_age)+'</td><td>'+key['Status']+'</td><td>'+str(LastUsedDate)+'</td></tr>'
                    elif exemption == 'false':
                        # Report non-exempt key, no action (not past thresholds)
                        line = '<tr><td>'+UserName+'</td><td>'+key['AccessKeyId']+'</td><td>'+str(key_age)+'</td><td>'+key['Status']+'</td><td>'+str(LastUsedDate)+'</td></tr>'
                    elif key_age >= int(os.environ['KEY_AGE_DELETE']) and exemption == 'true' and key['Status'] == 'Inactive':
                        # Delete exempt key only if already Inactive
                        delete_access_key(AccessKeyId, UserName, client_iam)
                        line = '<tr bgcolor= "#E6B0AA"><td>'+UserName+'</td><td>'+key['AccessKeyId']+'</td><td>'+str(key_age)+'</td><td>'+'DELETED'+'</td><td>'+str(LastUsedDate)+'</td></tr>'
                    elif exemption == 'true':
                        # Report exempt key, no action
                        line = '<tr bgcolor= "#D7DBDD"><td>'+UserName+'</td><td>'+key['AccessKeyId']+'</td><td>'+str(key_age)+'</td><td>'+key['Status']+'</td><td>'+str(LastUsedDate)+'</td></tr>'
                    else:
                        # This case should not happen
                        log.info('Not including in report, no conditions met for %s.', AccessKeyId)
                    htmlBody = htmlBody + line

                    # Log it
                    log.info('%s \t %s \t %s \t %s', UserName, key['AccessKeyId'], str(key_age), key['Status'])
    if str(htmlBody) == "":
        htmlBody = 'All Access Keys for this account are compliant.'
    return(htmlBody)


###############################################################################
# Generate IAM Credential Report
###############################################################################
def generate_credential_report(client_iam):
    try:
        log.info('Generating Credential Report')
        credential_report = client_iam.generate_credential_report()
        sleep(10)
    except ClientError as e:
        log.info('Error generating credential report: %s', e)


###############################################################################
# Process IAM Credential Report
###############################################################################
def get_credential_report(client_iam, report_counter):

    # check/re-check the state of the report
    generate_report = client_iam.generate_credential_report()
    if generate_report['State'] == 'COMPLETE':
        log.info('Report state: COMPLETE')
        try:
            credential_report = client_iam.get_credential_report()
            credential_report_csv = io.StringIO(credential_report['Content'].decode('utf-8'))
            reader = csv.DictReader(credential_report_csv)
            return list(reader)
        except ClientError as e:
            log.info('Error getting Report: %s', e)
    else:
        sleep(5)
        report_counter += 1
        if report_counter < 5:
            log.info('Still waiting on report generation')
            return get_credential_report(client_iam, report_counter)
        else:
            log.info('Credential report generation throttled - exit', exc_info=1)
            return exit


###############################################################################
# Take action on Access Keys
###############################################################################

# Delete Access Key
def delete_access_key(AccessKeyId, UserName, client):
    log.info("Deleting AccessKeyId %s for user %s", AccessKeyId, UserName)

    if os.environ['ARMED'] == 'true':
        response = client.delete_access_key(
            UserName=UserName,
            AccessKeyId=AccessKeyId
        )
    else:
        log.info("Not armed, no action taken")


# Disable Access Key
def disable_access_key(AccessKeyId, UserName, client):
    log.info("Disabling AccessKeyId %s for user %s", AccessKeyId, UserName)

    if os.environ['ARMED'] == 'true':
        response = client.update_access_key(
            UserName=UserName,
            AccessKeyId=AccessKeyId,
            Status='Inactive'
        )
    else:
        log.info("Not armed, no action taken")


###############################################################################
# Generate HTML and send to SES
###############################################################################
def process_message(htmlBody):
    htmlHeader = '<html><h1>Expiring Access Key Report for ' \
        + os.environ['ACCOUNT_NUMBER'] + ' - ' + os.environ['ACCOUNT_NAME'] + '</h1>' \
        + '<p>The following access keys are over ' \
        + os.environ['KEY_AGE_WARNING'] \
        + ' days old and will soon be marked inactive (' \
        + os.environ['KEY_AGE_INACTIVE'] \
        + ' days) and deleted (' \
        + os.environ['KEY_AGE_DELETE'] \
        + ' days).<br>' \
        + ' Grayed out rows are exempt via membership in IAM Group: ' \
        + os.environ['EXEMPT_GROUP'] + '</p>' \
        + '<table><tr><td><b>IAM User Name</b></td><td><b>Access Key ID</b></td><td><b>Key Age</b></td><td><b>Key Status</b></td><td><b>Last Used</b></td></tr>'
    htmlFooter = '</table></html>'
    html = htmlHeader + htmlBody + htmlFooter
    log.info('%s', html)

    # Optionally write the report to S3
    if os.environ['S3_ENABLED'] == 'true':
        client_s3 = boto3.client('s3')
        s3_key = 'access_key_audit_report_' + str(datetime.date.today()) + '.html'
        response = client_s3.put_object(
            Bucket=os.environ['S3_BUCKET'],
            Key=s3_key,
            Body=html
        )
    else:
        log.info("S3 report not enabled per environment variable setting")

    # Optionally send report via SES Email
    if os.environ['EMAIL_ENABLED'] == 'true':
        # Establish SES Client
        client_ses = boto3.client('ses')

        # Construct and Send Email
        try:
            response = client_ses.send_email(
                Destination={
                    'ToAddresses': [os.environ['EMAIL_TARGET']]
                },
                Message={
                    'Body': {
                        'Html': {
                            'Charset': "UTF-8",
                            'Data': html,
                        }
                    },
                    'Subject': {
                        'Charset': "UTF-8",
                        'Data': os.environ['EMAIL_SUBJECT'],
                    },
                },
                Source=os.environ['EMAIL_SOURCE']
                )
        except ClientError as e:
            log.info('Error: %s', e.response['Error']['Message'])
        else:
            log.info('Success. Message ID: %s', response['MessageId'])
    else:
        log.info("Email not enabled per environment variable setting")


###############################################################################
# Determine days since last change
###############################################################################
def object_age(last_changed):
    # Handle as string
    if type(last_changed) is str:
        last_changed_date = dateutil.parser.parse(last_changed).date()
    # Handle as native datetime
    elif type(last_changed) is datetime.datetime:
        last_changed_date = last_changed.date()
    else:
        return 0
    age = datetime.date.today() - last_changed_date
    return age.days
