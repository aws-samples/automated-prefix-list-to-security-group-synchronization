#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#


# Import Modules
import boto3
import sys
import os
import json

# Configure Local Service Clients
ssm = boto3.client('ssm')
ec2 = boto3.client('ec2')

# Environment Variables
paramstorepath = os.environ['parameter_store_path']
sgquotaservicecode = os.environ['security_group_quote_service_code']
sgquotaquotacode = os.environ['security_group_quote_quota_code']
sgrulepaddingpercentage = (int(os.environ['security_group_quota_padding_percentage'])/100)+1
sgrulepaddingbase = int(os.environ['security_group_quota_padding_base'])
batchsyncfn = os.environ['batch_sync_function_name']

# Log Handler which accepts a message as a string, a severity as an integer, and whether to send a message and whether
# to terminate the function with an error as boolean values.


def log_handler(message: str, severity: int, sendmessage: bool, terminate: bool):
    loglevel = int(os.environ['log_level'])  # Get the Log Level

    # If the severity is 1 (info) and the Log Level is configured for 1 (info)
    if severity == 1 and loglevel <= 1:

        # Printing the message here logs the output to the CloudWatch Logs Stream created for this function
        print("INFO: "+message)

        # If specified to send a message via SNS with the error
        if sendmessage:
            snsarn = os.environ['log_sns_arn']  # Get the SNS ARN configured for messages
            sns = boto3.client('sns')  # create the SNS client object

            # Publish the message with a generic subject to the configured SNS Topic
            sns.publish(
                TopicArn=snsarn,
                Message=message,
                Subject='INFO: AutoSG2PL log message'
            )

        # If specified to terminate the function, we exit with a non-zero error code which forces a cold start on the
        # next invocation of the Lambda in case there is any caching causing the error in question.
        if terminate:
            sys.exit(1)

    # If the severity is 2 (WARN) and the Log Level is configured for 1 (info) or 2 (warn)
    elif severity == 2 and loglevel <= 2:

        # Printing the message here logs the output to the CloudWatch Logs Stream created for this function
        print("WARNING: "+message)

        # If specified to send a message via SNS with the error
        if sendmessage:
            snsarn = os.environ['log_sns_arn']  # Get the SNS ARN configured for messages
            sns = boto3.client('sns')  # create the SNS client object

            # Publish the message with a generic subject to the configured SNS Topic
            sns.publish(
                TopicArn=snsarn,
                Message=message,
                Subject='WARNING: AutoSG2PL has encountered a non-critical issue'
            )

        # If specified to terminate the function, we exit with a non-zero error code which forces a cold start on the
        # next invocation of the Lambda in case there is any caching causing the error in question.
        if terminate:
            sys.exit(1)

    # If the severity is 3 (CRITICAL) and the Log Level is configured for 1 (info) or 2 (warn) or 3 (critical)
    elif severity == 3 and loglevel <= 3:

        # Printing the message here logs the output to the CloudWatch Logs Stream created for this function
        print("CRITICAL: "+message)

        # If specified to send a message via SNS with the error
        if sendmessage:
            snsarn = os.environ['log_sns_arn']  # Get the SNS ARN configured for messages
            sns = boto3.client('sns')  # create the SNS client object

            # Publish the message with a generic subject to the configured SNS Topic
            sns.publish(
                TopicArn=snsarn,
                Message=message,
                Subject='CRITICAL: AutoSG2PL has encountered a critical error'
            )

        # If specified to terminate the function, we exit with a non-zero error code which forces a cold start on the
        # next invocation of the Lambda in case there is any caching causing the error in question.
        if terminate:
            sys.exit(1)

    # If there is some unknown severity or unknown log level for some reason this acts as a catchall
    else:

        # Printing the message here logs the output to the CloudWatch Logs Stream created for this function
        print("UNKNOWN: "+message)

        # If specified to send a message via SNS with the error
        if sendmessage:
            snsarn = os.environ['log_sns_arn']  # Get the SNS ARN configured for messages
            sns = boto3.client('sns')  # create the SNS client object

            # Publish the message with a generic subject to the configured SNS Topic
            sns.publish(
                TopicArn=snsarn,
                Message=message,
                Subject='UNKNOWN: AutoSG2PL has encountered an UNKNOWN error'
            )

        # If specified to terminate the function, we exit with a non-zero error code which forces a cold start on the
        # next invocation of the Lambda in case there is any caching causing the error in question.
        if terminate:
            sys.exit(1)

# Get the current Value for the Max entries per SG quota


def get_sg_max_entries_quota_value(sqremote):
    sg_max_entries_sq = sqremote.get_service_quota(
        ServiceCode=sgquotaservicecode,
        QuotaCode=sgquotaquotacode
    )
    message = "get_service_quota call result: "+str(sg_max_entries_sq)
    log_handler(message, 1, False, False)
    return sg_max_entries_sq['Quota']['Value']

# Check to make sure the SG actually exists in the region


def sg_existence_check(sg: str):

    # Try describing the Security Group supplied
    try:
        response = ec2.describe_security_groups(
            GroupIds=[
                sg,
            ]
        )
        message = "describe_security_groups call result: "+str(response)
        log_handler(message, 1, False, False)

        # Determine if the response has 1 Security Group Supplied. if it is more than 1, something unexpected happened;
        # if it is less than 1, the Security Group doesn't actually exist.
        if len(response['SecurityGroups']) == 1:
            return True
        else:
            return False

    # If an exception occurs when executing the call it is assumed either the Security Group doesn't exists or there
    # is an issue checking it that needs to be resolved before continuing on.
    except Exception as e:
        message = "describe_security_groups call result: " + str(e)
        log_handler(message, 2, False, False)
        return False

# Make sure the mapping doesnt already exists


def parameter_not_exist_check(sg: str, region: str):

    # Attempt to get a parameter for the format that would be expected for the Security Group and Region pair
    try:
        nameval = paramstorepath+'/'+sg+'/'+region
        response = ssm.get_parameters(
            Names=[
                nameval,
            ],
            WithDecryption=False
        )
        message = "get_parameters call result: "+str(response)
        log_handler(message, 1, False, False)

        # If no parameters are returned, then true is returned to proceed
        if not response['Parameters']:
            return True
        else:
            return False

    # If an exception occurs when executing the call it is assumed either the parameter doesn't exist.
    except Exception as e:
        message = "get_parameters call result: " + str(e)
        log_handler(message, 1, False, False)
        return True

# Get all private IPs for network interfaces with the SG attached and return it in an list


def get_ips_in_sg(sg: str):

    # Create an empty list to populate with the IP addresses
    addrlist = list()

    # Call the built in paginator from Boto3 for describe_network_interfaces
    paginator = ec2.get_paginator('describe_network_interfaces')

    # Set our arguments for describe_network_interfaces
    operation_parameters = {'Filters': [{'Name': 'group-id', 'Values': [sg, ]}]}

    # Call the iterative function to get all pages
    page_iterator = paginator.paginate(**operation_parameters)

    # Loop through the pages
    for page in page_iterator:

        # Loop through the interfaces and then loop through the private IP addresses on the interface and add each
        # private IP address to the list we created at the start of this function.
        for interface in page['NetworkInterfaces']:
            for ipaddr in interface['PrivateIpAddresses']:
                addrlist.append(ipaddr['PrivateIpAddress'])

    # Now we log and return the full list of private IP addresses for ENIs associated with the Security Group
    message = "IPs returned for get_ips_in_sg are : "+str(addrlist)
    log_handler(message, 1, False, False)
    return addrlist

# Create a new prefix list to use


def create_prefixlist(sg: str, ec2remote, sqremote, region: str):

    # Call the Get_ips_in_sg to get a list of IP addresses that will be added in the creation of
    cidrs = get_ips_in_sg(sg)

    # Create an empty list that will be populated with the /32 CIDRs
    cidrstoadd = list()

    # Loop through the CIDRs returned to append the CIDR bits to the end and add it to the list
    for cidr in cidrs:
        value = {'Cidr': cidr + "/32"}
        cidrstoadd.append(value)

    # Determine the length with the padding percentage and base that will be the size of the Prefix List
    pllen = int(len(cidrstoadd)*sgrulepaddingpercentage+sgrulepaddingbase)
    message = "The PL length required is: "+str(pllen)
    log_handler(message, 1, False, False)

    # Get the current Quota for Max Entries per Security Group in the local account
    currentquota = get_sg_max_entries_quota_value(sqremote)

    # If the Prefix List length will exceed the Max Entries per Security Group quota in the local account, we error out
    # and request the user to increase the quota before proceeding. If the Prefix List is referenced in another account
    # errors will be handled when attempting to reference the prefix list in that account.
    if pllen > currentquota:
        message = "The prefix list length, "+str(pllen)+" ("+str(sgrulepaddingpercentage)+"*<number of IPs "\
            "associated with the Security Group>+"+str(sgrulepaddingbase)+"), exceeds the current quota, "\
            + str(currentquota)+", for maximum rules per Security Group. Please raise this quota first then execute"\
            "this script again."
        log_handler(message, 3, False, True)

    # If the Prefix List length is less than the quota, we proceed with creating the Prefix list
    else:

        # If the length of the list of CIDRs to add is less than 100, we create the Prefix List with the CIDRs populated
        # on create.
        if len(cidrstoadd) < 100:

            # Create the Prefix List populated with the CIDRs
            response = ec2remote.create_managed_prefix_list(
                PrefixListName=sg,
                Entries=cidrstoadd,
                MaxEntries=pllen,
                AddressFamily='IPv4'
            )
            message = "create_managed_prefix_list call result: "+str(response)
            log_handler(message, 1, False, False)

            # Return the Prefix List ID
            return response['PrefixList']['PrefixListId']

        # If the length of the list of CIDRs is greater than 100, we create a Prefix List, setting the size
        # appropriately but with no entries and call the Batch Sync Lambda Function to populate it. This is
        # because the Create_managed_prefix_list and modify_managed_prefix_list only allow up to 100 entries
        # to add per call. Batch Sync has an iterator to account for this API limit.
        else:

            # Create the empty Prefix List
            response = ec2remote.create_managed_prefix_list(
                PrefixListName=sg,
                MaxEntries=pllen,
                AddressFamily='IPv4'
            )
            message = "create_managed_prefix_list call result: " + str(response)
            log_handler(message, 1, False, False)

            # Get the ID for the Prefix List that was created
            pl = response['PrefixList']['PrefixListId']

            # Create the payload structure required to call the Batch Sync Lambda Function
            payload = {"sg": sg, "pl": pl, "region": region}
            message = "Invoking lambda " + str(batchsyncfn) + " with payload of " + str(payload)
            log_handler(message, 1, False, False)

            # Create the Lambda Client object
            lambdaclient = boto3.client('lambda')

            # Call the Batch Sync Function to initiate the initial synchronization
            lambdaresponse = lambdaclient.invoke(
                FunctionName=batchsyncfn,
                InvocationType='Event',
                LogType='None',
                Payload=bytes(json.dumps(payload), encoding='utf8')
            )
            message = "Lambda invocation returned" + str(lambdaresponse)
            log_handler(message, 1, False, False)

            # Return the Prefix List ID
            return response['PrefixList']['PrefixListId']

# create the parameters in parameter store with the mapping information


def create_parameter(sg: str, pl: str, region: str):

    # Attempt the parameter creation
    try:
        response = ssm.put_parameter(
            Name=paramstorepath+'/'+sg+'/'+region,
            Description='AutoSG2PL Mapping',
            Value=pl,
            Type='String',
            Overwrite=False,
            Tier='Standard',
            DataType='text'
        )
        message = "put_parameter call result: "+str(response)
        log_handler(message, 1, False, False)

    # If there is an exception on creation of the parameter, log the exception and return False to error out.
    except Exception as e:
        message = "put_parameter call result: " + str(e)
        log_handler(message, 2, False, False)
        return False

    # If the response returns a version greater than 0, we know the parameter created successfully. Otherwise we return
    # false to error out.
    try:
        if response['Version'] > 0:
            return True
        else:
            return False

    # If there was an error parsing the version from the response then the parameter most likely wasn't created
    # successfully so we log the error and return false to error out
    except Exception as e:
        message = "Could not parse the Parameter Version when creating the parameter: "+str(e)
        log_handler(message, 2, False, False)
        return False

# the main lambda function handler


def lambda_handler(event, context):

    # Get the supplied Security Group and store it in a variable
    if 'sg' in event.keys():
        sg = event['sg']
        message = "Lambda SG Called: "+str(sg)
        log_handler(message, 1, False, False)
    else:
        message = "A Security Group was not supplied in the sg input. This is a mandatory field."
        log_handler(message, 3, False, True)

    # Get the supplied Region and store it in a variable
    if 'region' in event.keys():
        region = event['region']
        message = "Lambda remote Region Called: "+str(region)
        log_handler(message, 1, False, False)
    else:
        message = "A region was not supplied in the region input. This is a mandatory field."
        log_handler(message, 3, False, True)

    # Set up the Service Quotas client in the supplied region
    sqremote = boto3.client('service-quotas', region_name=region)

    # Setup the EC2 client in the supplied region
    ec2remote = boto3.client('ec2', region_name=region)

    # Check if the Security Group actually exist in the local region and account
    if sg_existence_check(sg):

        # Make sure there isn't already a mapping for the Security Group specified and the region specified
        if parameter_not_exist_check(sg, region):

            # Create the Prefix List and populate it either directly or through the Batch Sync function
            try:
                plcreate = create_prefixlist(sg, ec2remote, sqremote, region)

            # If there was an error on creation of the Prefix List we log the error and exit with a non-zero exit code
            except Exception as e:
                message = "The Prefix List could not be created for some reason. Please try again later."\
                               " Error returned: "+str(e)
                log_handler(message, 3, False, True)

            # Create the parameter to store the mapping of Security Group to Region to Prefix List combination
            if create_parameter(sg, plcreate, region):
                message = "AutoSG2PL has configured "+sg+" to sync with "+plcreate+" successfully. An initial sync "\
                    "has already completed."
                log_handler(message, 1, False, False)
                return message

            # The rest of this is error handling
            else:
                message = "There was an error creating a mapping for this security group("+sg+") to the prefix list."
                log_handler(message, 3, False, True)
        else:
            message = "A mapping already exists for "+sg+" in "+region+" to a Prefix List in AutoSG2PL"
            log_handler(message, 3, False, True)
    else:
        message = "The security Group("+sg+") referenced, does not exist in this account or region."
        log_handler(message, 3, False, True)

