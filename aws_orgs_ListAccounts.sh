#!/bin/bash

# Set destination
output_file="aws_accounts_all.txt"

# List account in org
account_list=$(aws organizations list-accounts --output json)

# Parse only the account Id
account_ids=$(echo "$account_list" | jq -r '.Accounts[].Id')

# Write the account id list to file
echo "$account_ids" > $output_file