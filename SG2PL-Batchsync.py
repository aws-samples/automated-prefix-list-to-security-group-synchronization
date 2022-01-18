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
import time
import sys
import os
import math

# Configure Local Service Clients
ec2 = boto3.client('ec2')

# Environment Variables
sgquotaservicecode = os.environ['security_group_quote_service_code']
sgquotaquotacode = os.environ['security_group_quote_quota_code']
sgrulemaxutilizationpercentage = 1-(int(os.environ['security_group_quota_padding_percentage'])/100)

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
    message = "IPs returned for get_ips_in_sg are : " + str(addrlist)
    log_handler(message, 1, False, False)
    return addrlist

# Get all IPs in the Prefix List (We are assuming everything is a /32 and stripping the bit mask)


def get_ips_in_pl(pl: str, ec2remote):

    # Create an empty list to populate with the IP addresses
    addrlist = list()

    # Call the built in paginator from Boto3 for get_managed_prefix_list_entries
    paginator = ec2remote.get_paginator('get_managed_prefix_list_entries')

    # Set our arguments for get_managed_prefix_list_entries
    operation_parameters = {'PrefixListId': pl}

    # Call the iterative function to get all pages
    page_iterator = paginator.paginate(**operation_parameters)

    # Loop through the pages
    for page in page_iterator:

        # Loop through each entry in the page then if it is a /32 we strip the bits, otherwise we ignore the entry
        for entry in page['Entries']:
            if int(entry['Cidr'].split('/')[1]) == 32:
                addrlist.append(entry['Cidr'].split('/')[0])

    # Now we log and return the full list of IP addresses in the Prefix List
    message = "addrlist for get_ips_in_pl: "+str(addrlist)
    log_handler(message, 1, False, False)
    return addrlist

# Get the Max Entries and Current Version


def pl_info(pl: str, ec2remote):

    # Call describe_managed_prefix_lists to get its current configuration parameters
    plinfodata = ec2remote.describe_managed_prefix_lists(
        PrefixListIds=[
            pl,
        ]
    )

    # Log the return from describe_managed_prefix_lists
    message = "describe_managed_prefix_lists call result: "+str(plinfodata)
    log_handler(message, 1, False, False)

    # Return a dict with MaxEnt and Version fields from the Prefix List
    return {'MaxEnt': plinfodata['PrefixLists'][0]['MaxEntries'], 'Version': plinfodata['PrefixLists'][0]['Version']}

# Remove the CIDRs specified from the Prefix List specified


def remove_cidr_from_pl(pl: str, ips: set, version: str, ec2remote):

    # Create an empty list to populate the IPs as CIDRs
    entriestoremove = list()

    # Loop through the IPs and append the list with a dict with the IP in CIDR notation as a /32
    for ip in ips:
        value = {'Cidr': ip + "/32"}
        entriestoremove.append(value)

    # Log the list of dicts created above
    message = "Trying to remove: " + str(entriestoremove) + " from " + str(pl) + " using version " + str(version)
    log_handler(message, 1, False, False)

    # Paginate the list into separate lists no greater than 99 CIDRs each to account for the maximum of 100
    # entries in RemoveEntries per modify_managed_prefix_list call
    paginatedentriestoremove = [entriestoremove[i:i + 99] for i in range(0, len(entriestoremove), 99)]

    # Log the paginated list of lists created above
    message = "Paginated list of list:: trying to remove: " + str(paginatedentriestoremove) + " from "\
        + str(pl) + " using version " + str(version)
    log_handler(message, 1, False, False)

    # Loop through the paginated list of lists for entries to remove
    for page in paginatedentriestoremove:

        # Determine the current status of the Prefix List and if it is not in an acceptable state enter a loop to
        # check every second until it is ready.
        plstatus = pl_ready(pl, ec2remote)
        while not plstatus:
            time.sleep(1)
            plstatus = pl_ready(pl, ec2remote)

        # Get the Prefix List info, specifically the current list version
        version = pl_info(pl, ec2remote)['Version']

        # Attempt to call the modify_managed_prefix_list with the current page of entries to remove and log the return
        try:
            response = ec2remote.modify_managed_prefix_list(
                PrefixListId=pl,
                CurrentVersion=version,
                RemoveEntries=page
            )
            version = response['PrefixList']['Version']
            message = "modify_managed_prefix_list call result: " + str(response)
            log_handler(message, 1, False, False)

        # If an exception occurs, log it, send a message via SNS and terminate the function unsuccessfully.
        except Exception as e:
            message = "Removing new CIDRs from " + str(pl) + " was unsuccessful. Error returned: " + str(e)
            log_handler(message, 3, True, True)
    return version

# Add the CIDRs specified to the Prefix List specified


def add_cidr_to_pl(pl: str, ips: set, version: str, ec2remote):

    # Create an empty list to populate the IPs as CIDRs
    entriestoadd = list()

    # Loop through the IPs and append the list with a dict with the IP in CIDR notation as a /32
    for ip in ips:
        value = {'Cidr': ip + "/32"}
        entriestoadd.append(value)

    # Log the list of dicts created above
    message = "Trying to add: " + str(entriestoadd) + " to " + str(pl) + " using version " + str(version)
    log_handler(message, 1, False, False)

    # Paginate the list into separate lists no greater than 99 CIDRs each to account for the maximum of 100
    # entries in AddEntries per modify_managed_prefix_list call
    paginatedentriestoadd = [entriestoadd[i:i + 99] for i in range(0, len(entriestoadd), 99)]

    # Log the paginated list of lists created above
    message = "Paginated list of list:: trying to remove: " + str(paginatedentriestoadd) + " from " \
              + str(pl) + " using version " + str(version)
    log_handler(message, 1, False, False)

    # Loop through the paginated list of lists for entries to add
    for page in paginatedentriestoadd:

        # Determine the current status of the Prefix List and if it is not in an acceptable state enter a loop to
        # check every second until it is ready.
        plstatus = pl_ready(pl, ec2remote)
        while not plstatus:
            time.sleep(1)
            plstatus = pl_ready(pl, ec2remote)

        # Get the Prefix List info, specifically the current list version
        version = pl_info(pl, ec2remote)['Version']

        # Attempt to call the modify_managed_prefix_list with the current page of entries to add and log the return
        try:
            response = ec2remote.modify_managed_prefix_list(
                PrefixListId=pl,
                CurrentVersion=version,
                AddEntries=page
            )
            version = response['PrefixList']['Version']
            message = "modify_managed_prefix_list call result: "+str(response)
            log_handler(message, 1, False, False)

        # If an exception occurs, log it, send a message via SNS and terminate the function unsuccessfully.
        except Exception as e:
            message = "Adding new CIDRs to "+str(pl)+" was unsuccessful. Error returned: "+str(e)
            log_handler(message, 3, True, True)
    return version

# Update CIDRs in the PL


def update_cidrs_in_pl(pl: str, ipstoremove: set, ipstoadd: set, version: str, ec2remote):

    # Create an empty list to populate the IPs as CIDRs to add
    entriestoadd = list()

    # Loop through the IPs to add and append the list with a dict with the IP in CIDR notation as a /32
    for iptoadd in ipstoadd:
        value = {'Cidr': iptoadd + "/32"}
        entriestoadd.append(value)

    # Log the list of dicts created above
    message = "Bulk update: Trying to add: " + str(entriestoadd) + " to " + str(pl) + " using version " + str(version)
    log_handler(message, 1, False, False)

    # Create an empty list to populate the IPs as CIDRs to remove
    entriestoremove = list()

    # Loop through the IPs to remove and append the list with a dict with the IP in CIDR notation as a /32
    for iptoremove in ipstoremove:
        value = {'Cidr': iptoremove + "/32"}
        entriestoremove.append(value)

    # Log the list of dicts created above
    message = "Bulk update: Trying to remove: "+str(entriestoremove)+" from "+str(pl)+" using version "+str(version)
    log_handler(message, 1, False, False)

    # Attempt to call the modify_managed_prefix_list with the entries to add and remove and log the return
    try:
        response = ec2remote.modify_managed_prefix_list(
            PrefixListId=pl,
            CurrentVersion=version,
            AddEntries=entriestoadd,
            RemoveEntries=entriestoremove
        )
        message = "modify_managed_prefix_list call result: " + str(response)
        log_handler(message, 1, False, False)
        return response['PrefixList']['Version']

    # If an exception occurs, log it, send a message via SNS and terminate the function unsuccessfully.
    except Exception as e:
        message = "Updating new CIDRs in " + str(pl) + " was unsuccessful. Error returned: " + str(e)
        log_handler(message, 3, True, True)

# Get the status of the Prefix List


def pl_ready(pl: str, ec2remote):

    # Call describe_managed_prefix_lists
    plinfodata = ec2remote.describe_managed_prefix_lists(
        PrefixListIds=[
            pl,
        ]
    )

    # Log the return
    message = "modify_managed_prefix_list call result: "+str(plinfodata)
    log_handler(message, 1, False, False)

    # Parse the current State
    plstate = plinfodata['PrefixLists'][0]['State']

    # Go through various known and documented state possibilities and return True if the Prefix List is in a state
    # ready for modification, False if it is in a state not ready for modification but should naturally turn to a
    # state that is ready later, or call the error handler with a message to send via SNS and terminate the Function
    # if it is in a state that requires user intervention before proceeding.
    if plstate == 'create-in-progress':
        message = str(pl)+" PL is in a creating state."
        log_handler(message, 3, False, True)
    elif plstate == 'create-complete':
        return True
    elif plstate == 'create-failed':
        message = "The prefix list "+str(pl)+" is in a state of creation failed. Please delete remove the" \
                        "configuration for this sync and recreate it with a new prefix list."
        log_handler(message, 3, True, True)
    elif plstate == 'modify-in-progress':
        return False
    elif plstate == 'modify-complete':
        return True
    elif plstate == 'modify-failed':
        message = "There was an error modifying prefix list "+str(pl)+". The reason was: "\
                  + str(plinfodata['PrefixLists'][0]['StateMessage'])
        log_handler(message, 3, True, True)
    elif plstate == 'restore-in-progress':
        return False
    elif plstate == 'restore-complete':
        return True
    elif plstate == 'restore-failed':
        message = "The prefix list "+str(pl)+" is in a state of restore-failed. Please correct this so the "\
                        "status becomes modify-complete for the sync to resume successfully"
        log_handler(message, 3, True, True)
    elif plstate == 'delete-in-progress':
        message = "The prefix list "+str(pl)+" is currently being deleted. Please delete the AutoSG2PL "\
                        "configuration to prevent unnecessary invocations of the associated Lambda functions."
        log_handler(message, 3, True, True)
    elif plstate == 'delete-complete':
        message = "The prefix list "+str(pl)+" has been deleted. Please delete the AutoSG2PL configuration "\
                        "to prevent unnecessary invocations of the associated Lambda functions."
        log_handler(message, 3, True, True)
    elif plstate == 'delete-failed':
        message = "The prefix list "+str(pl)+" has been unsuccessfully deleted. Please either do an update "\
                        "on the prefix list or delete it completely and delete the AutoSG2PL configuration to "\
                        "prevent unnecessary invocations of the associated Lambda functions."
        log_handler(message, 3, True, True)
    else:
        message = "The prefix list "+str(pl)+" is in an unknown state of: "+str(plstate)+" Please make an "\
                        "update so it gets into a modify-complete state."
        log_handler(message, 3, True, True)

# Resize the Prefix List to account for Max Entries


def pl_resize(pl: str, currentquota: int, newplsize: int, ec2remote):

    # Determine the optimal new size based on the configured padding percentage
    newmaxent = math.ceil(newplsize / sgrulemaxutilizationpercentage)

    # If the optimal new size exceeds the quota, send a warning via SNS and resize to 1 less than the current quota
    if newmaxent > currentquota:
        message = "The prefix list " + str(pl) + " was resized to accommodate the latest sync but below the padding " \
            "percentage threshold set due to the current Max Entries per Security Group quota. Please request an " \
            "increase in Service Quotas to allow for greater than " + str(newmaxent) + " entries per Security Group " \
            "or lower your security_group_quota_padding_percentage threshold configured on the AutoSG2PL Batch Sync " \
            "Lambda Function under Environment Variables"
        log_handler(message, 2, True, False)
        newmaxent = int(currentquota - 1)

    # Try to resize the Prefix List to the new value. If the new value exceeds a quota in another account the error
    # is handled by the Prefix List resize function itself and then caught during the Prefix List status check.
    try:
        response = ec2remote.modify_managed_prefix_list(
            PrefixListId=pl,
            MaxEntries=newmaxent
        )
        message = "modify_managed_prefix_list max entries call result: " + str(response)
        log_handler(message, 1, False, False)
        return response['PrefixList']['Version']

    # If an exception occurs, log it, send a message via SNS and terminate the function unsuccessfully.
    except Exception as e:
        message = "Updating Max Entries for " + str(pl) + " was unsuccessful. Error returned: " + str(e)
        log_handler(message, 3, True, True)

# the main lambda function handler


def lambda_handler(event, context):

    # Get the supplied Security Group and store it in a variable. If none is supplied
    if 'sg' in event.keys():
        sg = event['sg']
        message = "Lambda SG Called: " + str(sg)
        log_handler(message, 1, False, False)
    else:
        message = "AutoSG2PL-BatchSync was called without a Security Group specified. The Event was: "+str(event)
        log_handler(message, 3, True, True)

    # Get the supplied Prefix List and store it in a variable
    if 'pl' in event.keys():
        pl = event['pl']
        message = "Lambda pl Called: " + str(pl)
        log_handler(message, 1, False, False)
    else:
        message = "AutoSG2PL-BatchSync was called without a Prefix List specified. The Event was: "+str(event)
        log_handler(message, 3, True, True)

    # Get the supplied Region and store it in a variable
    if 'region' in event.keys():
        region = event['region']
        message = "Lambda region Called: " + str(region)
        log_handler(message, 1, False, False)
    else:
        message = "AutoSG2PL-BatchSync was called without a Region specified. The Event was: " + str(event)
        log_handler(message, 3, True, True)

    # Create the Service Quotas client object in the remote region and log the object reference
    sqremote = boto3.client('service-quotas', region_name=region)
    message = "sqremote: "+str(sqremote)
    log_handler(message, 1, False, False)

    # Create the EC2 client object in the remote region and log the object reference
    ec2remote = boto3.client('ec2', region_name=region)
    message = "ec2remote: "+str(ec2remote)
    log_handler(message, 1, False, False)

    # Get the Private IP addresses for ENIs associated with the Security Group Specified
    sgiplist = get_ips_in_sg(sg)

    # Get the IP addresses stored in the Prefix List specified
    pliplist = get_ips_in_pl(pl, ec2remote)

    # Create a set with the IP addresses that are on the ENIs with the Security Group but not in the Prefix List
    itemstoadd = set(sgiplist) - set(pliplist)
    message = "IPs to add: "+str(itemstoadd)
    log_handler(message, 1, False, False)

    # Create a set with the IP addresses that are in the Prefix List but no on the ENIs with the Security Group
    itemstoremove = set(pliplist) - set(sgiplist)
    message = "IPs to remove: "+str(itemstoremove)
    log_handler(message, 1, False, False)

    # Determine the number of prefixes that will be in the Prefix List after the updates
    newpllength = len(pliplist) + len(itemstoadd) - len(itemstoremove)
    message = "New PL length: "+str(newpllength)
    log_handler(message, 1, False, False)

    # use pl_info to get the Max Entries and current version values for the Prefix List
    plinfo = pl_info(pl, ec2remote)

    # Get the current quota for Max Entries per Security Group in the local account in the region the Prefix List is in
    currentquota = get_sg_max_entries_quota_value(sqremote)

    # If the new prefix list length is greater than the quota (not including padding calculated later, call the
    # error handler to send a message via SNS and terminate the function
    if currentquota - newpllength < 1:
        message = "The prefix list "+str(pl)+" size exceeds the max quota of rules per security group of " +\
                str(currentquota)+" in "+str(region)+". Please request a limit increase through the Service "\
                "Quotas console so the security group can continue to sync to the prefix list."
        log_handler(message, 3, True, True)

    # If the new prefix list length exceeds percentage threshold set, raise a critical error via the log handler
    # and send a notification via SNS but do not terminate the function.
    elif newpllength / currentquota > sgrulemaxutilizationpercentage:
        message = "The prefix list "+str(pl)+" size exceeds the warning threshold of rules per security "\
                        "group in "+str(region)+". Please request a limit increase through the Service Quotas "\
                        "console to prevent an interruption in AutoSG2PL."
        log_handler(message, 3, True, False)

    # Resize the Prefix List if the new length exceeds the current Max Entries Value
    if plinfo['MaxEnt'] < newpllength:

        # Attempt to resize the prefix list
        pl_resize(pl, currentquota, newpllength, ec2remote)

        # Determine the current status of the Prefix List and if it is not in an acceptable state enter a loop to
        # check every second until it is ready. This also handles any errors that happen when resizing the Prefix List
        plstatus = pl_ready(pl, ec2remote)
        while not plstatus:
            time.sleep(1)
            plstatus = pl_ready(pl, ec2remote)

    # Prefix List Max Entries is large enough and the local account Max Entries per Security Group Quota is good
    else:
        # If there is something to add or remove and the number of items to add is less than 100 and the number
        # of items to remove is less than 100 then we make a bulk update to reduce the number of calls.
        if (len(itemstoadd) > 0 or len(itemstoremove) > 0) and len(itemstoadd) < 100 and len(itemstoremove) < 100:

            # Determine the current status of the Prefix List and if it is not in an acceptable state enter a loop to
            # check every second until it is ready.
            plstatus = pl_ready(pl, ec2remote)
            while not plstatus:
                time.sleep(1)
                plstatus = pl_ready(pl, ec2remote)

            # Log the bulk update
            message = "Bulk update: Removing " + str(itemstoremove) + " from " + str(pl) + " and adding " +\
                str(itemstoadd) + " to " + str(pl)
            log_handler(message, 1, False, False)

            # Call the bulk update function. Any errors are handled within the function so the return is ignored
            update_cidrs_in_pl(pl, itemstoremove, itemstoadd, plinfo['Version'], ec2remote)

        # If there is something to add or remove and either of the sets is greater than 100 items in length the add
        # and remove functions are called separately to allow for iteration to handle the max 100 entries to change
        # at a time.
        elif (len(itemstoadd) > 0 or len(itemstoremove) > 0) and (len(itemstoadd) > 100 or len(itemstoremove) > 100):

            # If there are items to remove, call the remove remove_cidr_from_pl function
            if len(itemstoremove) > 0:

                # Determine the current status of the Prefix List and if it is not in an acceptable state enter a
                # loop to check every second until it is ready.
                plstatus = pl_ready(pl, ec2remote)
                while not plstatus:
                    time.sleep(1)
                    plstatus = pl_ready(pl, ec2remote)

                # Log the items to be removed
                message = "Removing "+str(itemstoremove)+" from "+str(pl)
                log_handler(message, 1, False, False)

                # Call the remove CIDR function. Any errors are handled within the function so the return is ignored
                remove_cidr_from_pl(pl, itemstoremove, plinfo['Version'], ec2remote)

            # If there are items to add, call the remove add_cidr_to_pl function
            if len(itemstoadd) > 0:

                # Determine the current status of the Prefix List and if it is not in an acceptable state enter a
                # loop to check every second until it is ready.
                plstatus = pl_ready(pl, ec2remote)
                while not plstatus:
                    time.sleep(1)
                    plstatus = pl_ready(pl, ec2remote)

                # Log the items to be added
                message = "Adding "+str(itemstoadd)+" to "+str(pl)
                log_handler(message, 1, False, False)

                # Call the add CIDR function. Any errors are handled within the function so the return is ignored
                add_cidr_to_pl(pl, itemstoadd, pl_info(pl, ec2remote)['Version'], ec2remote)

        # If neither of the above conditions are met that means the Prefix List is already up to date
        else:
            message = "No CIDRs to update in "+str(pl)
            log_handler(message, 1, False, False)

    # Log and return a message for successful completion of the sync
    message = "sync completed successfully for "+sg+" to "+pl
    log_handler(message, 1, False, False)
    return message

