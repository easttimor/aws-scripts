# aws-scripts
## A collection of scripts and functions to make life in AWS easier
Author: Timothy Orr @easttim0r

## Current capabilities

### AWS CLI AssumeRole
Makes assuming an AWS IAM role easier in CLI
1. Start with a default profile - IAM User access key credentials
2. Script calls sts assume-role to a specific IAM Role
3. The temporary credentials are exported as environment variables
4. Begin issuing CLI/API calls as the Role principal, no need to use --profile

Pro-tip: alias this script in your shell profile as something like aws_{role}
Future enhancements:
* non-static variables

### AWS Rotate Access Key
Creates a new Access Key pair, deletes the old Access Key pair. For default, specific, or all profiles.

Assumes the default profile
./aws_rotate_access_key.sh

For a specific profile
./aws_rotate_access_key.sh -p abc

For a specific profiles
./aws_rotate_access_key.sh -p abc -p def

For all profiles
./aws_rotate_access_key.sh -a
