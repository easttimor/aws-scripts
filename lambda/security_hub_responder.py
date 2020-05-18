""" Function: Security Hub Responder
Purpose:
    Receives Events (presumed "source":"aws.securityhub")
    Parses for Failed event status indicating non-compliance
    Logs non-compliant resource information
    To-do: notification (SNS/SES) and auto-remediation actions
Trigger:
    Events (CloudWatch or EventBridge)
Environment Variables:
    LOG_LEVEL: (optional): sets the level for function logging
      valid input: critical, error, warning, info (default), debug
"""

import collections
import json
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


def lambda_handler(event, context):
    """
    Args:
        event (string): Security Hub event finding type
        context
    """

    if event['source'] == 'aws.securityhub':
        log.info("Security Hub Finding")
        for finding in event['detail']['findings']:
            process_security_hub_finding(finding)
    elif event['source'] == 'aws.config':
        log.info("Config Rule Finding")
        log.info(event)
        process_config_rule_finding(event)




def process_security_hub_finding(f):
    """ Parse each finding and log resource info
    Args:
        f (string): finding from event
    Returns:

    """
    finding = {}
    finding['status'] = f['Compliance']['Status']
    finding['severity_normalized'] = f['Severity']['Normalized']
    finding['severity_label'] = f['Severity']['Label']
    finding['account'] = f['AwsAccountId']

    # We only care about FAILED findings
    if finding['status'] == 'FAILED':

        # Multiple resources may exist
        for resource in f['Resources']:

            # We only care about resources, not the Account status
            if resource['Type'] != 'Account':
                log.info("Severity: %s / %s", finding['severity_normalized'], finding['severity_label'])
                log.info("Account: %s", finding['account'])
                log.info("Resource: %s", resource['Id'])

def process_config_rule_finding(event):
    """ Parse each finding and log resource info
    Args:
        f (string): finding from event
    Returns:

    """
    finding = {}
    finding['resourceType'] = event['detail']['resourceType']
    finding['resourceId'] = event['detail']['resourceId']
    finding['awsAccountId'] = event['detail']['awsAccountId']
    finding['configRuleName'] = event['detail']['configRuleName']

    log.info('Config Rule Name: %s', finding['configRuleName'])
    log.info('Resource Type: %s', finding['resourceType'])
    log.info('Resource ID: %s', finding['resourceId'])
    log.info("Account: %s", finding['awsAccountId'])