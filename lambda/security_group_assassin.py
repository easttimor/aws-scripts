###############################################################################
# Name:
#       Security Group Assassin
# Purpose:
#       Gets a list of all security groups
#       Looks for security groups with no attached ENIs
#       Outputs those security groups
#           with the assumption that they can be deleted
# Permissions:
#       in addition to default CloudWatch Logs
#       ec2:DeleteSecurityGroup
#       ec2:DescribeSecurityGroups
#       ec2:DescribeNetworkInterfaces
#       s3:PutObject
#       ses:SendEmail
# Environment Variables:
#       LOG_LEVEL: (optional): sets the level for function logging
#                  valid input: critical, error, warning, info (default), debug
# To Do:
#       paginate describe_security_groups
#       paginate describe_network_interfaces
###############################################################################

from botocore.exceptions import ClientError
import boto3
import collections
import datetime
import logging
import os

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
# Handler
###############################################################################
def lambda_handler(event, context):

    # Establish client, get list of security groups
    ec2_client = boto3.client('ec2')
    body = process_security_groups(ec2_client)

    # Process the report via SES and/or S3
    process_report(body)


###############################################################################
# Process Security Groups
###############################################################################
def process_security_groups(ec2_client):
    response = ec2_client.describe_security_groups()
    htmlBody = ''
    deletion_list = []

    # Evaluate each security group
    for sg in response['SecurityGroups']:
        log.debug('%s,%s,%s', sg['GroupId'], sg['VpcId'], sg['GroupName'])

        # reinitialize
        exempt = False

        interfaces = ec2_client.describe_network_interfaces(
            Filters=[
                {
                    'Name': 'group-id',
                    'Values': [
                        str(sg['GroupId'])
                    ]
                }
            ]
        )

        if not interfaces['NetworkInterfaces']:
            # Security Group has no attached ENI(s)
            log.info('Found %s,%s,%s', sg['GroupId'], sg['VpcId'], sg['GroupName'])

            # Get tags
            response = ec2_client.describe_tags(
                Filters=[
                    {
                        'Name': 'resource-id',
                        'Values': [sg['GroupId']]
                    },
                    {
                        'Name': 'resource-type',
                        'Values': ['security-group']
                    }
                ]
            )

            # Evaluate tags
            for item in response['Tags']:
                if 'Key' in item:
                    if item['Key'] == 'Exempt':
                        exempt = True
                        log.info('Exempt %s', sg['GroupId'])

            # Evaluate for deletion
            if (
                sg['GroupName'] != 'default' and
                not exempt
            ):

                # Delete ingress rules to remove dependencies
                for rule in sg['IpPermissions']:
                    response = ec2_client.revoke_security_group_ingress(
                        GroupId=sg['GroupId'],
                        IpPermissions=[rule]
                    )

                # Delete egress rules to remove dependencies
                for rule in sg['IpPermissionsEgress']:
                    response = ec2_client.revoke_security_group_egress(
                        GroupId=sg['GroupId'],
                        IpPermissions=[rule]
                    )

                # Add security group to list for deletion
                deletion_list.append(sg['GroupId'])

                # Report entry
                line = (
                    '<tr bgcolor= "#FFFFFF">'
                    '<td>{}</td>'
                    '<td>{}</td>'
                    '<td>{}</td>'
                    '<td>DELETE</td>'
                    '</tr>'
                    .format(sg['GroupId'], sg['VpcId'], sg['GroupName'])
                )
            else:
            # EXEMPT: Report only
                line = (
                    '<tr bgcolor= "#C0C0C0">'
                    '<td>{}</td>'
                    '<td>{}</td>'
                    '<td>{}</td>'
                    '<td>EXEMPT</td>'
                    '</tr>'
                    .format(sg['GroupId'], sg['VpcId'], sg['GroupName'])
                )

            # Add entry in report
            htmlBody = htmlBody + line

    # Send list of security groups for deletion
    results = delete_security_groups(ec2_client, deletion_list)

    # close and return htmlBody to report
    if str(htmlBody) == "":
        # Address the case of total compliance
        htmlBody = (
            '</table>'
            '<p>All Security Groups for this account are compliant.</p>'
            '</html>'
        )
    elif results:
        # Update report to notify of deletion issues
        line = (
            '</table>'
            '<p>The following security groups could not be deleted'
            'due to dependency issues. Please manually resolve: {}</p>'
            '</html>'
            .format(results)
        )
        htmlBody = htmlBody + line
    else:
        line = (
            '</table></html>'
        )
        htmlBody = htmlBody + line

    return(htmlBody)


###############################################################################
# Delete Security Group
###############################################################################
def delete_security_groups(ec2_client, deletion_list):

    dependency_list = []
    for sg in deletion_list:
        log.info('Delete %s', sg)
        try:
            response = ec2_client.delete_security_group(
                GroupId=sg
            )
        except:
            log.info('Dependency issue with %s',sg)
            dependency_list.append(sg)
    return dependency_list


###############################################################################
# Generate HTML and send to SES
###############################################################################
def process_report(htmlBody):
    htmlHeader = (
        '<html><h1>Security Group Report for {} - {} </h1>'
        '<p>The following security groups have no attached network interfaces</p>'
        '<p>Grayed out rows are exempt via tag: </p>'
        '<table>'
        '<tr><td><b>Security Group ID</b></td>'
        '<td><b>VPC ID</b></td>'
        '<td><b>Security Group Name</b></td></tr>'
        .format(os.environ['ACCOUNT_NUMBER'], os.environ['ACCOUNT_NAME'])
    )

    html = htmlHeader + htmlBody
    log.debug('%s', html)

    # Optionally write the report to S3
    if os.environ['S3_ENABLED'] == 'true':
        client_s3 = boto3.client('s3')
        s3_key = 'security_group_audit_report_' + str(datetime.date.today()) + '.html'
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