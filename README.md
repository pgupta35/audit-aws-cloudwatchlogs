audit cloudwatchlogs
============================
This stack will monitor cloudwatchlogs and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor cloudwatchlogs against best practices for you and send a report to the email address designated by the config.yaml AUDIT_AWS_CLOUDWATCHLOGS_ALERT_RECIPIENT value

## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-cloudwatchlogs/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_CLOUDWATCHLOGS_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_CLOUDWATCHLOGS_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_CLOUDWATCHLOGS_REGIONS`:
  * description: List of AWS regions to check. Default is all regions. Choices are us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,ap-south-1,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,eu-central-1,eu-west-1,eu-west-1,sa-east-1
  * default: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, ap-south-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1


## Optional variables with default

### `AUDIT_AWS_CLOUDWATCHLOGS_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all CLOUDWATCHLOGS alerts. Choices are kms-inventory
  * default: cloudwatchlogs-inventory

### `AUDIT_AWS_CLOUDWATCHLOGS_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner of the CLOUDWATCHLOGS object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `AUDIT_AWS_CLOUDWATCHLOGS_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

## Tags
1. Audit
1. Best Practices
1. Alert
1. cloudwatchlogs

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-cloudwatchlogs/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-cloudwatchlogs/master/images/icon.png "icon")

