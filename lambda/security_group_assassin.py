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
#       ec2:Describe*
# Environment Variables:
#       LOG_LEVEL: (optional): sets the level for function logging
#                  valid input: critical, error, warning, info (default), debug
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
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups()
    for sg in response['SecurityGroups']:
        log.debug('%s,%s,%s', sg['GroupId'], sg['VpcId'], sg['GroupName'])

        interfaces = ec2.describe_network_interfaces(
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
            log.info('%s,%s,%s', sg['GroupId'], sg['VpcId'], sg['GroupName'])
