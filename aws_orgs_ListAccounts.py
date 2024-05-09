import boto3
import json

# Set destination
output_file="aws_accounts_all.txt"

# Initialize client
organizations_client = boto3.client('organizations')

# List accounts in org
response = organizations_client.list_accounts()

# Print all
for account in response['Accounts']:
    print(account)

# Parse only the account Id
account_ids=[account['Id'] for account in response['Accounts']]

# Write the account id list to file
with open(output_file, 'w') as f:
    for account_id in account_ids:
        f.write(account_id + '\n')