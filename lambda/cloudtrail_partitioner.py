###############################################################################
# Function:
#       CloudTrail Partitioner
# Purpose:
#       Reads from consolidated CloudTrail bucket
#       Partitions Athena CloudTrail table on region, year, month, day
#       This speeds up Athena Queries and decreases data ingest (lower cost)
# Trigger:
#       CloudWatch Events scheduler
# Recommended Function Settings (varies by environment):
#       128 MB Memory
#       15 min Timeout
# Environment Variables:
#       LOG_LEVEL: (optional): sets the level for function logging
#                  valid input: critical, error, warning, info (default), debug
#       S3_BUCKET_INPUT: Bucket containing the CloudTrail logs
#       CLOUDTRAIL_PREFIX: Path to the logs (anything before /AWSLogs), or ""
#       PARTITION_DAYS: Number of days in the past to create partitions for
#       S3_BUCKET_OUTPUT: Bucket for Athena query results
#       DATABASE: Athena database name (e.g. default)
#       TABLE_PREFIX: Athena table prefix (e.g. cloudtrail)
# Credit:
#       This code orginated with duo-labs cloudtrail-partitioner
#       https://github.com/duo-labs/cloudtrail-partitioner
#       This concept is written about here:
#       https://medium.com/@alsmola/partitioning-cloudtrail-logs-in-athena-29add93ee070
###############################################################################

import boto3
import collections
import datetime
import json
import logging
import os
import re
import time
from pathlib import Path

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
# ATHENA QUERY
###############################################################################
class athena_querier:
    database = ""
    output_bucket = ""
    athena = None

    def __init__(self, database, output):
        self.database = database
        self.output_bucket = output
        self.athena = boto3.client("athena")

        self.query(
            "CREATE DATABASE IF NOT EXISTS {db} {comment}".format(
                db=self.database, comment="COMMENT 'Created by CloudTrail Partitioner'"
            ),
            context=None,
        )

    def query(self, query, context=None, skip_header=True):
        logging.debug("Making query {}".format(query))

        # Make query request dependent on whether the context is None or not
        if context is None:
            response = self.athena.start_query_execution(
                QueryString=query,
                ResultConfiguration={"OutputLocation": self.output_bucket},
            )
        else:
            response = self.athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext=context,
                ResultConfiguration={"OutputLocation": self.output_bucket},
            )

        self.wait_for_query_to_complete(response["QueryExecutionId"])

        # Paginate results and combine them
        rows = []
        paginator = self.athena.get_paginator("get_query_results")
        response_iterator = paginator.paginate(
            QueryExecutionId=response["QueryExecutionId"]
        )
        row_count = 0
        for response in response_iterator:
            for row in response["ResultSet"]["Rows"]:
                row_count += 1
                if row_count == 1:
                    if skip_header:
                        # Skip header
                        continue
                rows.append(self.extract_response_values(row))
        return rows

    def extract_response_values(self, row):
        result = []
        for column in row["Data"]:
            result.append(column.get("VarCharValue", ""))
        return result

    def wait_for_query_to_complete(self, queryExecutionId):
        """
        Returns when the query completes successfully, or raises an exception if it fails or is canceled.
        Waits until the query finishes running.
        """

        while True:
            response = self.athena.get_query_execution(
                QueryExecutionId=queryExecutionId
            )
            state = response["QueryExecution"]["Status"]["State"]
            log.debug('State:%s', state)
            if state == "SUCCEEDED":
                return True
            if state == "FAILED" or state == "CANCELLED":
                raise Exception(
                    "Query entered state {state} with reason {reason}".format(
                        state=state,
                        reason=response["QueryExecution"]["Status"][
                            "StateChangeReason"
                        ],
                    )
                )
            logging.debug(
                "Sleeping 1 second while query {} completes".format(queryExecutionId)
            )
            time.sleep(1)


###############################################################################
# MAIN
###############################################################################
def main():

    # Read config
    config = {}
    if 'S3_BUCKET_INPUT' in os.environ:
        config['s3_bucket_input'] = os.environ['S3_BUCKET_INPUT']
    if 'CLOUDTRAIL_PREFIX' in os.environ:
        config['cloudtrail_prefix'] = os.environ['CLOUDTRAIL_PREFIX']
    if 'PARTITION_DAYS' in os.environ:
        config['partition_days'] = int(os.environ['PARTITION_DAYS'])
    if 'S3_BUCKET_OUTPUT' in os.environ:
        config['s3_bucket_output'] = os.environ['S3_BUCKET_OUTPUT']
    if 'DATABASE' in os.environ:
        config['database'] = os.environ['DATABASE']
    if 'TABLE_PREFIX' in os.environ:
        config['table_prefix'] = os.environ['TABLE_PREFIX']

    if 's3_bucket_input' not in config:
        raise Exception("No configuration info found")

    # Check the credentials and get the current region and account id
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    logging.info("Using AWS identity: {}".format(identity["Arn"]))
    current_account_id = identity["Account"]
    current_region = boto3.session.Session().region_name

    # Get the default output bucket if one is not given
    if config['s3_bucket_output'] == 'default':
        config['s3_bucket_output'] = "aws-athena-query-results-{}-{}".format(
            current_account_id, current_region
        )

    # Set Athena database and set bucket query
    db_context = {"Database": config['database']}
    athena = athena_querier(config['database'], "s3://"+config['s3_bucket_output'])

    # Get all regions (needed for creating partitions)
    ec2 = boto3.client("ec2")
    region_response = ec2.describe_regions(AllRegions=True)["Regions"]
    regions = []
    for region in region_response:
        regions.append(region["RegionName"])

    # Ensure the CloudTrail log folder has the expected contents
    s3 = boto3.client("s3")
    log_path_prefix = config["cloudtrail_prefix"]

    # Ensure we're running in the same region as the bucket
    bucket_location = s3.get_bucket_location(Bucket=config["s3_bucket_input"])["LocationConstraint"]
    if bucket_location is None:
        bucket_location = "us-east-1"
    if current_region != bucket_location:
        raise Exception("This application must be run from the same region as the bucket. Current location: {}; Bucket location: {}".format(current_region, bucket_location))

    # Sanity check that everything is well-formed
    resp = s3.list_objects_v2(
        Bucket=config["s3_bucket_input"],
        Prefix=log_path_prefix,
        Delimiter="/",
        MaxKeys=1,
    )

    if "CommonPrefixes" not in resp or len(resp["CommonPrefixes"]) == 0:
        exit(
            "ERROR: S3 bucket has no contents.  Ensure you have logs at s3://{bucket}/{path}".format(
                bucket=config["s3_bucket_input"], path=log_path_prefix
            )
        )

    if resp["CommonPrefixes"][0]["Prefix"] != "AWSLogs/":
        exit(
            "ERROR: S3 bucket path is incorrect.  Ensure you have logs at s3://{bucket}/{path}/AWSLogs".format(
                bucket=config["s3_bucket_input"], path=log_path_prefix
            )
        )

    # Identify all accounts in this bucket and what their prefix paths are
    log_path_prefix = log_path_prefix + "AWSLogs/"
    resp = s3.list_objects_v2(
        Bucket=config["s3_bucket_input"],
        Prefix=log_path_prefix,
        Delimiter="/",
    )
    accounts = []

    for prefix in resp["CommonPrefixes"]:
        prefix = prefix["Prefix"]
        # prefix is something like 'AWSLogs/123456789012/' or 'AWSLogs/o-123a123b12/'
        directory_name = prefix[len(log_path_prefix): -1]
        # directory_name should now be just 123456789012 or o-123a123b12

        if directory_name.startswith("o-"):
            organization_directory_response = s3.list_objects_v2(
                Bucket=config["s3_bucket_input"], Prefix=prefix, Delimiter="/"
            )
            for org_prefix in organization_directory_response["CommonPrefixes"]:
                org_prefix = org_prefix["Prefix"]
                account_id = org_prefix[len(prefix): -1]
                accounts.append({"account_id": account_id, "path_prefix": org_prefix})
        elif re.match("^[0-d]{12}$", directory_name):
            accounts.append({"account_id": directory_name, "path_prefix": prefix})
        else:
            log.info("Unexpected folder: {}".format(directory_name))

    for account in accounts:

        # Create tables and partitions for each account
        account_id = account['account_id']
        log.info("Processing table and partitions for account id: %s", account_id)

        cloudtrail_log_path = "s3://{bucket}/{path}/CloudTrail/".format(
            bucket=config["s3_bucket_input"], path=account["path_prefix"]
        )

        table_name = config["table_prefix"] + "_" + account_id

        # Set up table
        query = """CREATE EXTERNAL TABLE IF NOT EXISTS `{table_name}` (
            `eventversion` string COMMENT 'from deserializer',
            `useridentity` struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>> COMMENT 'from deserializer',
            `eventtime` string COMMENT 'from deserializer',
            `eventsource` string COMMENT 'from deserializer',
            `eventname` string COMMENT 'from deserializer',
            `awsregion` string COMMENT 'from deserializer',
            `sourceipaddress` string COMMENT 'from deserializer',
            `useragent` string COMMENT 'from deserializer',
            `errorcode` string COMMENT 'from deserializer',
            `errormessage` string COMMENT 'from deserializer',
            `requestparameters` string COMMENT 'from deserializer',
            `responseelements` string COMMENT 'from deserializer',
            `additionaleventdata` string COMMENT 'from deserializer',
            `requestid` string COMMENT 'from deserializer',
            `eventid` string COMMENT 'from deserializer',
            `resources` array<struct<arn:string,accountid:string,type:string>> COMMENT 'from deserializer',
            `eventtype` string COMMENT 'from deserializer',
            `apiversion` string COMMENT 'from deserializer',
            `readonly` string COMMENT 'from deserializer',
            `recipientaccountid` string COMMENT 'from deserializer',
            `serviceeventdetails` string COMMENT 'from deserializer',
            `sharedeventid` string COMMENT 'from deserializer',
            `vpcendpointid` string COMMENT 'from deserializer')
            PARTITIONED BY (region string, year string, month string, day string)
            ROW FORMAT SERDE
            'com.amazon.emr.hive.serde.CloudTrailSerde'
            STORED AS INPUTFORMAT
            'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
            OUTPUTFORMAT
            'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
            LOCATION '{cloudtrail_log_path}'""".format(
            table_name=table_name, cloudtrail_log_path=cloudtrail_log_path
        )
        # Run Athena query to create table if required
        athena.query(query, db_context)

        today = datetime.datetime.today()
        # Create partitions
        for day_difference in range(-1, config['partition_days']):
            partition_date = today - datetime.timedelta(days=day_difference)
            year = "{:0>4}".format(partition_date.year)
            month = "{:0>2}".format(partition_date.month)
            day = "{:0>2}".format(partition_date.day)

            log.info(
                "Creating partition for {table} for {year}-{month}-{day}".format(
                    table=table_name, year=year, month=month, day=day
                )
            )
            query = "ALTER TABLE {table_name} ADD IF NOT EXISTS \n".format(table_name=table_name)
            for region in regions:
                query += "PARTITION (region='{region}',year='{year}',month='{month}',day='{day}') location '{cloudtrail_log_path}{region}/{year}/{month}/{day}'\n".format(
                    region=region,
                    year=year,
                    month=month,
                    day=day,
                    cloudtrail_log_path=cloudtrail_log_path,
                )

            # Run Athena query
            athena.query(query, db_context)

    return True


###############################################################################
# HANDLER
###############################################################################
def lambda_handler(event, context):
    return main()
