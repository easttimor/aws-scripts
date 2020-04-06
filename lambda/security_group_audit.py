###############################################################################
# Purpose:
#
# Permissions:
#       config:GetComplianceDetailsByResource
#       ec2:DescribeNetworkInterfaces
#       ec2:DescribeSecurityGroups
#       s3:PutObject
#       ses:SendEmail
#       ses:SendRawEmail
# Environment Variables:
#       LOG_LEVEL: (optional): sets the level for function logging
#                  valid input: critical, error, warning, info (default), debug
#       EMAIL_SOURCE: send from address for the email, authorized in SES
#       EMAIL_SUBJECT: subject line for the email
#       EMAIL_TARGET: default email address if event fails to pass a valid one
# To-do:
#
###############################################################################

from botocore.exceptions import ClientError
import boto3
import collections
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
    client_config = boto3.client('config')

    response = client_config.describe_compliance_by_resource(
        ResourceType='AWS::EC2::SecurityGroup',
        ComplianceTypes=[
            'NON_COMPLIANT',
        ],
    )

    # Process each non-compliant Security Group
    html = '<html><h1>Non-Compliant Security Groups</h1>'
    for resource in response['ComplianceByResources']:

        client_ec2 = boto3.client('ec2')

        # Try/Catch gracefully handles non-Compliant security groups that no longer exist
        try:
            security_groups_response = client_ec2.describe_security_groups(
                GroupIds=[resource['ResourceId']]
            )

            security_group = security_groups_response['SecurityGroups'][0]
            group_name = security_group['GroupName']
            group_id = security_group['GroupId']
            group_description = security_group['Description']
            log.info('Group ID: %s', group_id)
            log.debug('Group Name: %s', group_name)
            log.debug('Description: %s', group_description)
            html_sg = '<h2>'+group_id+': '+group_name+'</h2><p>Description: '+group_description + \
                '</p><table><tr style="font-weight:bold" bgcolor="#D5DBDB"><td>Protocol</td><td>Port Range</td><td>Source</td></tr>'

            # Process each rule for the Security Group
            for perm in security_group['IpPermissions']:
                # Process protocol
                if str(perm['IpProtocol']) == '-1':
                    Protocol = 'All'
                else:
                    Protocol = str(perm['IpProtocol'])

                # Process PortRange
                if 'FromPort' not in perm:
                    PortRange = 'All'
                elif perm['FromPort'] == -1:
                    PortRange = 'All'
                elif perm['FromPort'] != perm['ToPort']:
                    PortRange = str(perm['FromPort'])+'-'+str(perm['ToPort'])
                else:
                    PortRange = str(perm['FromPort'])

                # Process Source
                try:
                    Source = str(perm['IpRanges'][0]['CidrIp'])
                except:
                    Source = str(perm['UserIdGroupPairs'][0]['GroupId'])
                else:
                    Source = 'All'

                log.debug(Protocol + '\t' + PortRange + '\t' + Source + '\t')
                # Append row to html body table
                html_sg = html_sg + '<tr><td>' + Protocol + '</td><td>' + \
                    PortRange + '</td><td>' + Source + '</td></tr>'

            # Close the table for the security group
            html_sg = html_sg + '</table>'
            log.debug(html_sg)
            # Append
            html = html + html_sg
            log.debug(html)

            interfaces = client_ec2.describe_network_interfaces(
                Filters=[
                    {
                        'Name': 'group-id',
                        'Values': [
                            str(resource['ResourceId'])
                        ]
                    }
                ]
            )
            try:
                html = html + '<p>Attached network interfaces</p><table><tr style="font-weight:bold" bgcolor="#D5DBDB"><td>NetworkInterfaceId</td><td>PrivateIpAddress</td><td>Description</td></tr>'
                for interface in interfaces['NetworkInterfaces']:
                    log.debug(interface['NetworkInterfaceId'] + '\t' +
                              interface['PrivateIpAddress'] + '\t' + interface['Description'])
                    html = html + '<tr><td>' + interface['NetworkInterfaceId'] + '</td><td>' + \
                        interface['PrivateIpAddress'] + '</td><td>' + \
                        interface['Description'] + '</td></tr>'
                html = html + '</table>'
            except:
                log.info('No attached resources')
        except:
            log.debug(resource['ResourceId'] + ' \t' + 'does not exist')

        # close the message body
        html = html + '</html>'
        log.debug(html)
    send_message(html)


###############################################################################
# SES Send Email
###############################################################################
def send_message(html):
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
