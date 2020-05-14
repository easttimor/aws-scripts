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
#       s3:putObject
#       ses:SendEmail
#       ses:SendRawEmail
# Environment Variables:
#       ACCOUNT_NAME: AWS Account (friendly) Name
#       ACCOUNT_NUMBER: AWS Account Number
#       ARMED: Set to "true" to take action on keys;
#               "false" limits to reporting
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
    generate_credential_report(client_iam, report_counter=0)

    # Get Credential Report
    report = get_credential_report(client_iam)

    # Process Users in Credential Report
    body = process_users(client_iam, report)

    # Process message for SES
    process_message(body)


###############################################################################
# Generate IAM Credential Report
###############################################################################
def generate_credential_report(client_iam, report_counter, max_attempts=5):

    generate_report = client_iam.generate_credential_report()

    if generate_report['State'] == 'COMPLETE':
        # Report is generated, proceed in Handler
        return None
    else:
        # Report is not ready, try again
        report_counter += 1
        log.info('Generate credential report count %s',report_counter)
        if report_counter <  max_attempts:
            log.info('Still waiting on report generation')
            sleep(10)
            return generate_credential_report(client_iam, report_counter)
        else:
            log.info('Credential report generation throttled - exit')
            return exit


###############################################################################
# Process IAM Credential Report
###############################################################################
def get_credential_report(client_iam):

    credential_report = client_iam.get_credential_report()
    credential_report_csv = io.StringIO(credential_report['Content'].decode('utf-8'))
    reader = csv.DictReader(credential_report_csv)
    return list(reader)


###############################################################################
# Process each user and key in the Credential Report
###############################################################################
def process_users(client_iam, report):
    # Initialize message content
    html_body = ''
    line = ''

    # Access the credential report and process it
    for row in report:
        # A row is a unique IAM user
        user_name = row['user']
        log.debug("Processing user: %s", user_name)
        exemption = False
        if user_name != '<root_account>':

            # Test group exemption
            groups = client_iam.list_groups_for_user(UserName=user_name)
            for g in groups['Groups']:
                if g['GroupName'] == os.environ['EXEMPT_GROUP']:
                    exemption = True
                    log.info('User is exempt via group membership in: %s', g['GroupName'])

            # Process Access Keys for user
            access_keys = client_iam.list_access_keys(UserName=user_name)
            for key in access_keys['AccessKeyMetadata']:
                key_age = object_age(key['CreateDate'])
                access_key_id = key['AccessKeyId']

                # get time of last key use
                get_key = client_iam.get_access_key_last_used(
                    AccessKeyId=access_key_id
                )

                # last_used_date value will not exist if key not used
                last_used_date = get_key['AccessKeyLastUsed'].get('LastUsedDate')
                if (
                    not last_used_date and
                    key_age >= int(os.environ['KEY_USE_THRESHOLD']) and
                    not exemption
                ):
                    # Key has not been used and has exceeded age threshold
                    # NOT EXEMPT: Delete unused
                    delete_access_key(access_key_id, user_name, client_iam)
                    line = (
                        '<tr bgcolor= "#E6B0AA">'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>DELETED</td>'
                        '<td>{}</td>'
                        '</tr>'
                        .format(user_name, key['AccessKeyId'],
                                str(key_age), str(last_used_date))
                    )
                    html_body += line

                # Process keys older than warning threshold
                if key_age < int(os.environ['KEY_AGE_WARNING']):
                    continue

                if (
                    key_age >= int(os.environ['KEY_AGE_DELETE']) and
                    not exemption
                ):
                    # NOT EXEMPT: Delete
                    delete_access_key(access_key_id, user_name, client_iam)
                    line = (
                        '<tr bgcolor= "#E6B0AA">'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>DELETED</td>'
                        '<td>{}</td>'
                        '</tr>'
                        .format(user_name, key['AccessKeyId'],
                                str(key_age), str(last_used_date))
                    )
                elif (
                    key_age >= int(os.environ['KEY_AGE_INACTIVE']) and
                    not exemption
                ):
                    # NOT EXEMPT: Disable
                    disable_access_key(access_key_id, user_name, client_iam)
                    line = (
                        '<tr bgcolor= "#F4D03F">'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '</tr>'
                        .format(user_name, key['AccessKeyId'],
                                str(key_age), key['Status'], str(last_used_date))
                    )
                elif not exemption:
                    # NOT EXEMPT: Report
                    line = (
                        '<tr bgcolor= "#FFFFFF">'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '</tr>'
                        .format(user_name, key['AccessKeyId'],
                                str(key_age), key['Status'], str(last_used_date))
                    )
                elif (
                    key_age >= int(os.environ['KEY_AGE_DELETE']) and
                    exemption and
                    key['Status'] == 'Inactive'
                ):
                    # EXEMPT: Delete if Inactive
                    delete_access_key(access_key_id, user_name, client_iam)
                    line = (
                        '<tr bgcolor= "#E6B0AA">'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>DELETED</td>'
                        '<td>{}</td>'
                        '</tr>'
                        .format(user_name, key['AccessKeyId'],
                                str(key_age), str(last_used_date))
                    )
                elif exemption:
                    # EXEMPT: Report
                    line = (
                        '<tr bgcolor= "#D7DBDD">'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '<td>{}</td>'
                        '</tr>'
                        .format(user_name, key['AccessKeyId'],
                                str(key_age), key['Status'], str(last_used_date))
                    )
                else:
                    raise Exception('Unhandled case for Access Key %s', key['AccessKeyId'])
                html_body += line

                # Log it
                log.info('%s \t %s \t %s \t %s', user_name, key['AccessKeyId'], str(key_age), key['Status'])
    if str(html_body) == "":
        html_body = 'All Access Keys for this account are compliant.'
    return(html_body)


###############################################################################
# Take action on Access Keys
###############################################################################

# Delete Access Key
def delete_access_key(access_key_id, user_name, client):
    log.info("Deleting AccessKeyId %s for user %s", access_key_id, user_name)

    if str(os.environ['ARMED']).lower() == 'true':
        response = client.delete_access_key(
            UserName=user_name,
            AccessKeyId=access_key_id
        )
    else:
        log.info("Not armed, no action taken")


# Disable Access Key
def disable_access_key(access_key_id, user_name, client):
    log.info("Disabling AccessKeyId %s for user %s", access_key_id, user_name)

    if str(os.environ['ARMED']).lower() == 'true':
        response = client.update_access_key(
            UserName=user_name,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
    else:
        log.info("Not armed, no action taken")


###############################################################################
# Generate HTML and send to SES
###############################################################################
def process_message(html_body):
    html_header = (
        '<html><h1>Expiring Access Key Report for {} - {} </h1>'
        '<p>The following access keys are over {} days old '
        'and will soon be marked inactive ({} days) and deleted ({} days).</p>'
        '<p>Grayed out rows are exempt via membership in IAM Group: {}</p>'
        '<table>'
        '<tr><td><b>IAM User Name</b></td>'
        '<td><b>Access Key ID</b></td>'
        '<td><b>Key Age</b></td>'
        '<td><b>Key Status</b></td>'
        '<td><b>Last Used</b></td></tr>'
        .format(os.environ['ACCOUNT_NUMBER'], os.environ['ACCOUNT_NAME'],
                os.environ['KEY_AGE_WARNING'], os.environ['KEY_AGE_INACTIVE'],
                os.environ['KEY_AGE_DELETE'], os.environ['EXEMPT_GROUP'])
    )

    html_footer = '</table></html>'
    html = html_header + html_body + html_footer
    log.info('%s', html)

    # Optionally write the report to S3
    if str(os.environ['S3_ENABLED']).lower() == 'true':
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
    if str(os.environ['EMAIL_ENABLED']).lower() == 'true':
        # Establish SES Client
        client_ses = boto3.client('ses')

        # Construct and Send Email
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
