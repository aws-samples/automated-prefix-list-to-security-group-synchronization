# AutoSG2PL

This solution is designed to automatically synchronize private IP addresses for ENIs associated with a Security Group
to a Managed Prefix List in the same or different region as the Security Group. This can enable strict IP based filtering across region or when crossing a Transit Gateway, as well as when using a middle box appliance in a VPC where security group referencing is not supported. 

## Getting Started

 1.  Launch the CloudFormation Template making sure to fill in the SNSRecipientEmail Parameter used to email error notices.
    (note: The CloudFormation Template must be launched in each region you want to reference Security Groups in but is not
    needed in the regions where the Prefix Lists will reside.)
 2.  Run the AutoSG2PL-OnBoarding Lambda referencing the Security group you wish to synchronize, and the region you want the Prefix
    List to reside. (example using AWS CLI: `aws lambda invoke --function AutoSG2PL-OnBoard --invocation-type RequestResponse --payload '{ "sg": "sg-bbbbb22222", "region": "us-east-1" }' output.json`)
 3.  Repeat Step 2 for each Security group to Region pairing you which to configure synchronizations for
 4.  Enable the Event Bridge rule to start synchronizing the security group to the prefix list on a schedule.

## Function Descriptions

 - Bulk-Batch-Initiator: This Function reads all mapping of SG, Region, Prefix list combinations as stored in Parameter Store and 
    invokes the Batch-Sync lambda for each mapping.
 - Batch-Sync: This Function gets all IP addresses for ENIs associated   
 - OnBoard: This Function creates a Prefix List in the specified region, and stores the mapping of Security Group, Prefix List and
    region in Parameter store. It also does an initial population of the Prefix List with IPs associated with the Security Group.
   
## Considerations

 - When launching the CloudFormation, the EventBridge Rule that triggers the Bulk Batch Initiator function is created in a disabled state to avoid unwanted charges. Make sure to enable the rule after creating a mapping for the first time with the OnBoarding function so the prefix lists will stay in sync with the security group(s) membership(s). 
 - IPv6 is not supported in this solution today.
 - IPs are added to the prefix list as 32-bit CIDRs and this does not support summarization, this can be suboptimal for a large set of IP addresses.
 - Inserting CIDRs that are not 32-bits in length into the prefix list can cause unintended effects with this solution. It is highly recommended not to update the prefix lists manually.
 - This solution currently runs as a batch update on a schedule which means there can be a delay between an update to an ENI with respect to IP association to a security group and the prefix list being updated. 
 - When using a prefix list in a security group, the packet is evaluated that the source IP address matches a CIDR within the prefix list. Care should be taken with access to create or modify routes that could cause unintended access based on source IP filtering. 
