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


# Import modules
import boto3
import json
import os
import sys
import time

# Configure Local Service Clients
ssm = boto3.client('ssm')
lambdaclient = boto3.client('lambda')

# Environment Variables
batchsyncfn = os.environ['batch_sync_function_name']
paramstorepath = os.environ['parameter_store_path']

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

# Parse the Parameter store path search to get Security Group, Prefix List and Region mapping groups


def paramparser(input_response):

    # Create an empty List that we will store all Mappings in
    params = list()

    # Loop through the parameters to get each parameter
    for parameter in input_response['Parameters']:

        # Get the name field from the parameter and split it up by its' sections
        name = parameter['Name'].split('/')

        # Get the region as the last index in the split Name field
        region = name[int(len(name)-1)]

        # Get the Security Group ID as the second to last index in the Name Field
        sg = name[int(len(name)-2)]

        # Get the Prefix List ID which is the Value of the parameter
        pl = parameter['Value']

        # Append the params list with a dict of the mapping information
        params.append({"sg": sg, "pl": pl, "region": region})
    return params

# Loop through the mappings and invoke the Batch Sync Lambda for each


def run_update(paramsinput):

    # Loop through the mappings
    for payload in paramsinput:

        # Log the invocation and what payload it is being invoked with
        message = "Invoking lambda "+str(batchsyncfn)+" with payload of "+str(payload)
        log_handler(message, 1, False, False)

        # Invoke the Lambda with the payload
        response = lambdaclient.invoke(
            FunctionName=batchsyncfn,
            InvocationType='Event',
            LogType='None',
            Payload=bytes(json.dumps(payload),  encoding='utf8')
        )
        time.sleep(1)
        # Log the return from the invocation
        message = "Lambda invocation returned"+str(response)
        log_handler(message, 1, False, False)

# Main Lambda Handler function that takes no input and gets all configured mappings to sync from Parameter store
# runs them through the paramparser and then passes them to the run_update function to invoke the Batch Sync
# Lambda Function


def lambda_handler(event, context):

    # Set up the Paginator for get_parameters_by_path
    paginator = ssm.get_paginator('get_parameters_by_path')

    # Set up the arguments to pass to get_parameters_by_path
    operation_parameters = {'Path': paramstorepath, 'Recursive': True, 'WithDecryption': False}

    # Run the call to get a paginated return
    page_iterator = paginator.paginate(**operation_parameters)

    # Loop through the paginated return
    for page in page_iterator:

        # Log each page
        message = "get_parameters_by_path call result: " + str(page)
        log_handler(message, 1, False, False)

        # Parse the mappings to get a list of dicts
        parsed_sgs = paramparser(page)

        # Pass the list of mappings to the run_update function to invoke the Batch Sync Lambda Function
        run_update(parsed_sgs)

