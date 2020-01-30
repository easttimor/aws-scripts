#!/usr/bin/env bash
#
# Setup:
#   chmod +x ./aws_rotate_access_key.sh
#
# Execute:
#	Assumes the default profile
#   ./aws_rotate_access_key.sh
#
#	For a specific profile
#	./aws_rotate_access_key.sh -p abc
#
#	For a specific profiles
#	./aws_rotate_access_key.sh -p abc -p def
#
#	For all profiles
#	./aws_rotate_access_key.sh -a
#
# Description:
#   Creates a new access key and deletes the old one
#
# Assumptions:
#	IAM Permissions to do this
#	Properly configured credentials file

# Allow script to accept alternative values
profile_count=0
while [ $# -gt 0 ]; do
		case $1 in
			# Allows you to call multiple profiles
			# ex: -p test -p dev -p prod
			# This will overwrite the profiles array
			-p | --profile)
				shift
				profiles[$((profile_count++))]="$1"
				;;
			-r | --region)
				shift
				region="$1"
				;;
			# Allows you to cycle through all profiles in ~/.aws/credentials
			# This will overwrite the profiles array
			-a | --all-profiles)
				profiles=($(awk -F [ '/^\[/ {split($2,arr,"]"); print arr[1]}' ~/.aws/credentials))
				;;
			*)
				echo "usage: ${BASH_SOURCE[0]} [ -p | --profile <value> ] [ -r | --region <value> ]"
				return 2>/dev/null || exit # Allows script to exit whether sourced or ran normally
				;;
		esac
		shift
done

[ -z "${profiles[0]}" ] && profiles[0]=default
[ -z "$region" ] && region=us-east-1

unset  AWS_SESSION_TOKEN
export AWS_REGION="$region"

for profile in "${profiles[@]}"; do

	echo -e "\\nCurrent Profile: $profile"

	# Get caller user name
	echo "Current principal"
	current_user=$(basename "$(aws sts get-caller-identity --profile "$profile" --query 'Arn' --output text)")

	# Check for success and end iteration if the get-caller-identity call failed
	if [ -z $current_user ]; then
		echo "Could not make API call with profile ${profile}"
		continue
	else
		echo "User name: $current_user"
	fi

	# Load IAM Keys
	old_keys=($(aws iam list-access-keys  --profile "$profile" --query 'AccessKeyMetadata[].AccessKeyId' --output text))
	index=0
	for key in "${old_keys[@]}"; do
		# Check for success and end iteration if the list-access-keys call failed
		if [ -z $key ]; then
			echo "Failed to list current access keys for profile ${profile}."
			continue
		else
			echo "Current Access Key Id #$((++index)): $key"
		fi
	done

	# Delete second key if it exists
	if [ -n "${old_keys[1]}" ]; then
		echo "Deleting current access key #2"
		aws iam delete-access-key --access-key-id "${old_keys[1]}" --user-name "$current_user" --profile "$profile"
	fi

	# Create new key
	echo "Creating new access key"
	new_key=($(aws iam create-access-key --user-name "$current_user" --profile "$profile" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text))
	echo "New Access Key Id: ${new_key[0]} for ${profile}"

	# Delete first key
	echo "Deleting previous key"
	aws iam delete-access-key --access-key-id "${old_keys[0]}" --user-name "$current_user" --profile "$profile"

	# Load key material into local credentials file
	echo "Updating profile $profile for the new access key"
	aws configure set aws_access_key_id "${new_key[0]}" --profile "$profile"
	aws configure set aws_secret_access_key "${new_key[1]}" --profile "$profile"

	# Sleep to avoid race condition with read before write credentials file
	sleep 5
done