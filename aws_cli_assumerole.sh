#! /bin/bash
# 
# Dependencies:
#   brew install jq
#
# Setup:
#   chmod +x ./aws-cli-assumerole.sh
#
# Execute:
#   source ./aws-cli-assumerole.sh
#
# Description:
#   Makes assuming an AWS IAM role (+ exporting new temp keys) easier

unset  AWS_SESSION_TOKEN
export AWS_REGION=<UPDATE WITH AWS REGION e.g. us-east-1>

account=<UPDATE WITH AWS ACCOUNT NUMBER e.g. 012345678910>
role=<UPDATE WITH IAM ROLE NAME>
session=<UPDATE WITH SESSION NAME>

echo "CURRENT PRINCIPAL"
current_user=$(aws sts get-caller-identity --profile default)
echo $current_user
echo ""
temp_role=$(aws sts assume-role \
                    --role-arn "arn:aws:iam::${account}:role/${role}" \
                    --role-session-name ${session} \
                    --profile default)
echo "ASSUMED ROLE"
export AWS_ACCESS_KEY_ID=$(echo $temp_role | jq .Credentials.AccessKeyId | xargs)
export AWS_SECRET_ACCESS_KEY=$(echo $temp_role | jq .Credentials.SecretAccessKey | xargs)
export AWS_SESSION_TOKEN=$(echo $temp_role | jq .Credentials.SessionToken | xargs)

env | grep -i AWS_

echo ""
echo "UPDATED PRINCIPAL"
current_user=$(aws sts get-caller-identity)
echo $current_user
