###############################################################################
# Config Rule IAM User Active Remediation
#
# Input: CloudWatch Event, initiated by Config Rule non-compliant resource
# Config Rule: IAM User Active
# Description:
#   Receives a ResourceId of a non-compliant IAM User.
#   Looks up the user, determines exempt status via IAM Group membership
#   If non-exempt, removes all pre-reqs and deletes the IAM user.
# Environment Variables:
#   LOG_LEVEL (optional): sets the level for function logging
#       valid input: critical, error, warning, info (default), debug
#   GROUP_EXEMPTION (required):
#       valid input: any string. Should match an existing IAM Group.
#       example use case: mission critical account, "service" account
#
###############################################################################

from botocore.exceptions import ClientError
import boto3
import collections
import datetime
import json
import logging
import os
import sys

logger = logging.getLogger()
logger.setLevel(logging.INFO)
armed = "false"

###############################################################################
# LOGGING CONFIG
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
# HANDLER
###############################################################################
def lambda_handler(event, context):

    log.info(event)

    # Establish an AWS Config client
    client_config = boto3.client("config")

    # Parse CloudWatch Event
    eventDetail = event["detail"]
    resourceId = eventDetail["resourceId"]
    log.info("Type: %s", event["detail-type"])
    log.info("Rule: %s", eventDetail["configRuleName"])
    log.info("Message: %s", eventDetail["messageType"])
    log.info("Compliance: %s", eventDetail["newEvaluationResult"]["complianceType"])
    log.info("Account: %s", event["account"])
    log.info(
        "ResourceId: %s",
        eventDetail["newEvaluationResult"]["evaluationResultIdentifier"][
            "evaluationResultQualifier"
        ]["resourceId"],
    )

    # Only process if the event state change is to NON_COMPLIANT
    if eventDetail["newEvaluationResult"]["complianceType"] == "NON_COMPLIANT":
        try:
            process_non_compliant_resource(client_config, resourceId)
        except ClientError as e:
            log.info("Resource ID error: %s", e)
            return None


###############################################################################
# PROCESS IAM USER "RESOURCE"
###############################################################################
def process_non_compliant_resource(client_config, resourceId):
    # Discover Resource Name
    try:
        response = client_config.list_discovered_resources(
            resourceType="AWS::IAM::User", resourceIds=[resourceId]
        )
    except ClientError as e:
        log.info("Error with resource name: %s", e)
        sys.exit(1)

    # username value from resourceName key
    if response["resourceIdentifiers"]:
        user = response["resourceIdentifiers"][0]["resourceName"]
        log.info("User: %s", user)
    else:
        log.info("Empty resource returned")
        sys.exit(1)

    # Establish an AWS IAM client
    client_iam = boto3.client("iam")

    # User may be exempt via Group Membership
    status = process_group_exemption(client_iam, user)

    # Handle Pre-Reqs - Can't delete user if these exist
    if armed == "true" and status == "valid":
        # Delete User Pre-reqs
        process_ssh_key(client_iam, user)
        process_service_specific_credential(client_iam, user)
        process_inline_policies(client_iam, user)
        process_attached_managed_policies(client_iam, user)
        process_permission_boundary(client_iam, user)
        process_group_membership(client_iam, user)
        process_mfa(client_iam, user)

        # Delete User
        delete_user(client_iam, user)
    else:
        log.info("No action: User is exempt or function is not armed")


###############################################################################
# GROUP EXEMPTION: ALLOWS NON-COMPLIANT ACCOUNTS TO REMAIN UNTOUCHED
###############################################################################
def process_group_exemption(client_iam, user):
    response = client_iam.list_groups_for_user(UserName=user)
    inc = 0
    status = "valid"
    for group in response["Groups"]:
        group_arn = response["Groups"][inc]["Arn"]
        group_name = response["Groups"][inc]["GroupName"]
        if group_name == os.environ["GROUP_EXEMPTION"]:
            log.info("User is exempt via group membership")
            status = "exempt"
        inc += 1
    return status


###############################################################################
# ALL REMAINING FUNCTIONS ADDRESS PRE-REQUISITES FOR IAM USER DELETION
###############################################################################
def process_ssh_key(client_iam, user):
    response = client_iam.list_ssh_public_keys(UserName=user)
    inc = 0
    for key in response["SSHPublicKeys"]:
        ssh_public_key_id = response["SSHPublicKeys"][inc]["SSHPublicKeyId"]
        log.info("Detected Public SSH Key Id: %s", ssh_public_key_id)
        inc += 1


def process_service_specific_credential(client_iam, user):
    response = client_iam.list_service_specific_credentials(UserName=user)
    inc = 0
    for credential in response["ServiceSpecificCredentials"]:
        service = response["ServiceSpecificCredentials"][inc]["ServiceName"]
        credential_id = response["ServiceSpecificCredentials"][inc][
            "ServiceSpecificCredentialId"
        ]
        log.info("Detected Service Specific Credential: %s %s", service, credential_id)
        inc += 1


def process_inline_policies(client_iam, user):
    response = client_iam.list_user_policies(UserName=user)
    inc = 0
    for policy in response["PolicyNames"]:
        log.info("Delete In-Line User Policy: %s", response["PolicyNames"][inc])
        policy_name = response["PolicyNames"][inc]
        response = client_iam.delete_user_policy(UserName=user, PolicyName=policy_name)
        inc += 1


def process_attached_managed_policies(client_iam, user):
    response = client_iam.list_attached_user_policies(UserName=user)
    inc = 0
    for policy in response["AttachedPolicies"]:
        log.info(
            "Detach User Policy: %s", response["AttachedPolicies"][inc]["PolicyArn"]
        )
        policy_arn = response["AttachedPolicies"][inc]["PolicyArn"]
        client_iam.detach_user_policy(UserName=user, PolicyArn=policy_arn)
        inc += 1


def process_permission_boundary(client_iam, user):
    response = client_iam.get_user(UserName=user)
    try:
        boundary_arn = response["User"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
        log.info("Boundary ARN: %s", boundary_arn)
        response = client_iam.delete_user_permissions_boundary(UserName=user)
    except:
        pass


def process_group_membership(client_iam, user):
    response = client_iam.list_groups_for_user(UserName=user)
    inc = 0
    for group in response["Groups"]:
        group_arn = response["Groups"][inc]["Arn"]
        group_name = response["Groups"][inc]["GroupName"]
        if group_name != os.environ["GROUP_EXEMPTION"]:
            log.info("Removing as member of: %s %s", group_name, group_arn)
            remove_user = client_iam.remove_user_from_group(
                GroupName=group_name, UserName=user
            )
        else:
            log.info("User is exempt via group membership")
        inc += 1


def process_mfa(client_iam, user):
    response = client_iam.list_mfa_devices(UserName=user)
    inc = 0
    for device in response["MFADevices"]:
        device_id = response["MFADevices"][inc]["SerialNumber"]
        log.info("Deactivate MFA Device: %s", user)
        client_iam.deactivate_mfa_device(UserName=user, SerialNumber=device_id)
        log.info("Delete MFA Device: %s", device_id)
        client_iam.delete_virtual_mfa_device(SerialNumber=device_id)
        inc += 1


def delete_user(client_iam, user):
    try:
        client_iam.delete_user(UserName=user)
        log.info("Delete IAM User: %s", user)
    except ClientError as e:
        log.info("Error deleting user: %s %s", user, e)

