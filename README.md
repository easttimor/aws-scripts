# aws-scripts
## A collection of scripts and functions to make life in AWS easier
Author: Timothy Orr @easttim0r

## Current capabilities

### AWS CLI AssumeRole (Shell)
Makes assuming an AWS IAM role easier in CLI
1. Start with a default profile - IAM User access key credentials
2. Script calls sts assume-role to a specific IAM Role
3. The temporary credentials are exported as environment variables
4. Begin issuing CLI/API calls as the Role principal, no need to use --profile

Pro-tip: alias this script in your shell profile as something like aws_{role}

Future enhancements:
* non-static variables

### AWS Rotate Access Key (Shell)
Creates a new Access Key pair, deletes the old Access Key pair. For default, specific, or all profiles.

Assumes the default profile
./aws_rotate_access_key.sh

For a specific profile
./aws_rotate_access_key.sh -p abc

For a specific profiles
./aws_rotate_access_key.sh -p abc -p def

For all profiles
./aws_rotate_access_key.sh -a

### Acess Key Assassin (Lambda/Python)
Scans all Access Keys in an AWS account. Sets keys to Inactive or Delete based on configurable age values. Deletes unused keys based on configurable age values. Optionally sends an HTML formatted report via SES or writes it to S3. Optionally works in report-only mode with no actions taken. Best to begin in report-only mode until you get comfortable.

1. Reads the credential report
2. Determines the age of each access key
3. Builds a report of all keys older than KEY_AGE_WARNING
4. Takes action (inactive/delete) on non-compliant Access Keys

Future enhancements:
* Terraform 
* Paired with EventBridge to schedule trigger
* Code-defined execution role with appropriate permissions

### Security Group Assassin (Lambda/Python)
Scans an AWS account for unused security groups. The group is considered unused of no ENIs are attached to it. This function can work passively, simply reporting the unused groups, and this is how I would recommend using it initially. Once you get comfortable, "arm" the function and it will attempt to delete the security groups for you. 

1. Gets a list of all security groups
2. Looks for security groups with no attached ENIs
3. Outputs those security groups to choice of log, SES, S3
4. Optionally attempts to delete non-compliant security groups

Future enhancements:
* Terraform 
* Paired with EventBridge to schedule trigger
* Code-defined execution role with appropriate permissions