"""
Name:
    Security Group Assassin
Purpose:
    Gets a list of all security groups
    Looks for security groups with no attached ENIs
    Optionally reports to log, SES, S3
    Optionally attempts to delete non-compliant security groups
Permissions:
    (in addition to default CloudWatch Logs)
    ec2:DeleteSecurityGroup
    ec2:DescribeSecurityGroups
    ec2:DescribeNetworkInterfaces
    ec2:RevokeSecurityGroup*
    s3:PutObject
    ses:SendEmail
Environment Variables:
    ACCOUNT_NAME: AWS Account (friendly) Name
    ACCOUNT_NUMBER: AWS Account Number
    ARMED: Set to "true" to take action on keys; "false" limits to reporting
    EMAIL_ENABLED: used to enable or disable the SES emailed report
    EMAIL_SOURCE: send from address for the email, authorized in SES
    EMAIL_SUBJECT: subject line for the email
    EMAIL_TARGET: default email address if event fails to pass a valid one
    LOG_LEVEL: (optional): sets the level for function logging valid input: critical, error, warning, info (default), debug
    S3_ENABLED: set to "true" and provide S3_BUCKET if the audit report should be written to S3
    S3_BUCKET: bucket name to write the audit report to if S3_ENABLED is set to "true"
    TAG_EXEMPTION_KEY: comma delimited tag Key to ignore the security group
    TAG_EXEMPTION_VALUE: comma delimited tag Value to ignore the security group
To Do:
    paginate describe_security_groups
    paginate describe_network_interfaces
    better handling of groups with dependencies
"""

from botocore.exceptions import ClientError
from distutils.util import strtobool
import boto3
import collections
import datetime
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
        "critical": logging.CRITICAL,
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG,
    },
)

# Lambda initializes a root logger that needs to be removed in order to set a
# different logging config
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)

logging.basicConfig(
    format="%(asctime)s.%(msecs)03dZ [%(name)s][%(levelname)-5s]: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=LOG_LEVELS[os.environ.get("LOG_LEVEL", "").lower()],
)

log = logging.getLogger(__name__)


###############################################################################
# Handler
###############################################################################
def lambda_handler(event, context):

    # Load configuration values
    config = {}
    config["tag_exemption_key"] = os.environ["TAG_EXEMPTION_KEY"].lower().split(",")
    config["tag_exemption_value"] = os.environ["TAG_EXEMPTION_VALUE"].lower().split(",")
    config["armed"] = strtobool(os.environ["ARMED"])
    config["account_number"] = os.environ["ACCOUNT_NUMBER"]
    config["account_name"] = os.environ["ACCOUNT_NAME"]
    config["s3_enabled"] = strtobool(os.environ["S3_ENABLED"])
    config["s3_bucket"] = os.environ["S3_BUCKET"]
    config["email_enabled"] = strtobool(os.environ["EMAIL_ENABLED"])
    config["email_target"] = os.environ["EMAIL_TARGET"]
    config["email_subject"] = os.environ["EMAIL_SUBJECT"]
    config["email_source"] = os.environ["EMAIL_SOURCE"]

    # Establish client, get list of security groups
    ec2_client = boto3.client("ec2")
    report_body = process_security_groups(ec2_client, config)

    # Process the report via SES and/or S3
    process_report(report_body, config)


def process_security_groups(ec2_client, config):
    """Evaluate all security groups
    Args:
        ec2_client: boto3 service client for EC2
        config (dict): global configs for the fuction
    Returns:
        html_body (string): html formatted report of security group status
    """
    # Get list of Security Groups
    response = ec2_client.describe_security_groups()

    # initialize
    html_body = ""
    results = ""
    deletion_list = []

    # Evaluate each security group
    for sg in response["SecurityGroups"]:

        # reinitialize for each security group
        exempt = False

        # get list of attached ENI for specific security group
        interfaces = ec2_client.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [str(sg["GroupId"])]}]
        )

        # ignore security groups with network interfaces
        if interfaces["NetworkInterfaces"]:
            continue

        # Security group has no attached ENI(s)
        log.info(
            json.dumps(
                {
                    "security_group_id": sg["GroupId"],
                    "vpc_id": sg["VpcId"],
                    "security_group_name": sg["GroupName"],
                }
            )
        )

        # Get tags for the security group
        response = ec2_client.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [sg["GroupId"]]},
                {"Name": "resource-type", "Values": ["security-group"]},
            ]
        )

        # Evaluate tags to determine exemption
        for item in response["Tags"]:
            for index, key in enumerate(config["tag_exemption_key"]):
                try:
                    if (
                        "Key" in item
                        and str(item["Key"]).lower() == key
                        and str(item["Value"]).lower()
                        == config["tag_exemption_value"][index]
                    ):
                        exempt = True
                        log.info(
                            json.dumps(
                                {
                                    "security_group_id": sg["GroupId"],
                                    "status": "exempt",
                                    "key": item["Key"],
                                    "value": item["Value"],
                                }
                            )
                        )
                        break
                except IndexError as error:
                    log.info(
                        json.dumps(
                            {
                                "Error": error,
                                "Message": "Must have equal number of entries for TAG_EXEMPTION_KEY as TAG_EXEMPTION_VALUE",
                            }
                        )
                    )

        # Evaluate for deletion
        if sg["GroupName"] != "default" and not exempt:

            # Process only if function is armed
            if config["armed"]:

                # Delete ingress rules to remove dependencies
                for rule in sg["IpPermissions"]:
                    response = ec2_client.revoke_security_group_ingress(
                        GroupId=sg["GroupId"], IpPermissions=[rule]
                    )

                # Delete egress rules to remove dependencies
                for rule in sg["IpPermissionsEgress"]:
                    response = ec2_client.revoke_security_group_egress(
                        GroupId=sg["GroupId"], IpPermissions=[rule]
                    )

                # Add security group to list for deletion
                deletion_list.append(sg["GroupId"])

            # Report entry
            line = (
                '<tr bgcolor= "#FFFFFF">'
                "<td>{}</td>"
                "<td>{}</td>"
                "<td>{}</td>"
                "<td>DELETE</td>"
                "</tr>".format(sg["GroupId"], sg["VpcId"], sg["GroupName"])
            )
        else:
            # EXEMPT: Report only
            line = (
                '<tr bgcolor= "#C0C0C0">'
                "<td>{}</td>"
                "<td>{}</td>"
                "<td>{}</td>"
                "<td>EXEMPT</td>"
                "</tr>".format(sg["GroupId"], sg["VpcId"], sg["GroupName"])
            )

        # Add entry in report
        html_body += line

    # If ARMED, send list of security groups for deletion
    if config["armed"]:
        results = delete_security_groups(ec2_client, deletion_list)

    # close and return html_body to report
    if not html_body:
        # Address the case of total compliance
        html_body = (
            "</table>"
            "<p>All Security Groups for this account are compliant.</p>"
            "</html>"
        )
    elif results:
        # Update report to notify of deletion issues
        line = (
            "</table>"
            "<p>The following security groups could not be deleted "
            "due to dependency issues.<br>Please manually resolve: {}</p>"
            "</html>".format(results)
        )
        html_body += line
    else:
        line = "</table></html>"
        html_body = html_body + line

    return html_body


def delete_security_groups(ec2_client, deletion_list):
    """Delete Security Group
    Args:
        ec2_client: boto3 service client for EC2
        deletion_list (list[string]): list of security group ids for deletion
    Returns:
        dependency_list (list[string]): list of security group ids that cannot be deleted due to dependencies
    """
    dependency_list = []
    for sg in deletion_list:
        try:
            response = ec2_client.delete_security_group(GroupId=sg)
        except ClientError as error:
            if error.response["Error"]["Code"] == "DependencyViolation":
                log.info(
                    json.dumps({"security_group_id": sg, "status": "dependency issue"})
                )
                dependency_list.append(sg)
            else:
                raise error
        log.info(
            json.dumps({"security_group_id": sg, "action": "ec2.delete_security_group"})
        )
    return dependency_list


def process_report(html_body, config):
    """Generate HTML; send to S3 and/or SES
    Args:
        html_body (string): html-formatted body for report
        config (dict): global configs for the fuction
    Returns:
        none
    """
    html_header = (
        "<html><h1>Security Group Report for {} - {} </h1>"
        "<p>The following security groups have no attached network interfaces.</p>"
        "<p>Grayed out rows are exempt via tag: </p>"
        "<table>"
        "<tr><td><b>Security Group ID</b></td>"
        "<td><b>VPC ID</b></td>"
        "<td><b>Security Group Name</b></td></tr>".format(
            config["account_number"], config["account_name"]
        )
    )

    html = html_header + html_body
    log.debug("%s", html)

    # Optionally write the report to S3
    if config["s3_enabled"]:
        client_s3 = boto3.client("s3")
        s3_key = "security_group_audit_report_{}.html".format(datetime.date.today())
        response = client_s3.put_object(
            Bucket=config["s3_bucket"], Key=s3_key, Body=html
        )
        log.info(
            json.dumps(
                {
                    "action": "s3.put_object",
                    "status": "success",
                    "detail": s3_key,
                }
            )
        )
    else:
        log.info(
            json.dumps(
                {
                    "action": "s3.put_object",
                    "status": "not_enabled",
                }
            )
        )

    # Optionally send report via SES Email
    if config["email_enabled"]:
        # Establish SES Client
        client_ses = boto3.client("ses")

        # Construct and Send Email
        response = client_ses.send_email(
            Destination={"ToAddresses": [config["email_target"]]},
            Message={
                "Body": {
                    "Html": {
                        "Charset": "UTF-8",
                        "Data": html,
                    }
                },
                "Subject": {
                    "Charset": "UTF-8",
                    "Data": config["email_subject"],
                },
            },
            Source=config["email_source"],
        )
        log.info(
            json.dumps(
                {
                    "action": "ses.send_email",
                    "status": "success",
                    "detail": response["MessageId"],
                }
            )
        )
    else:
        log.info(
            json.dumps(
                {
                    "action": "ses.send_email",
                    "status": "not enabled",
                }
            )
        )
