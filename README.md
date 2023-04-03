<p align="center"><img src="https://static.commonfate.io/logos/commonfate/screen/light_purple/common_fate_logo_light_purple.svg" height="40" /></p>

<h1 align="center">Common Fate AWS Provider</h1>

<p align="center">An <a href="https://docs.commonfate.io/common-fate/next/providers/providers">Access Provider</a> for automating permissions to AWS.</p>

<p align="center">
<a align="center"  href="https://join.slack.com/t/commonfatecommunity/shared_invite/zt-q4m96ypu-_gYlRWD3k5rIsaSsqP7QMg"><img src="https://img.shields.io/badge/slack-commonfate-1F72FE.svg?logo=slack" alt="slack" /></a>
</p>
<br/>

## Access

This Access Provider provisions temporary account assignments for AWS IAM Identity Center Permission Sets. When making an access request, users will specify the following parameters:

| Parameter | Description               |
| --------- | ------------------------- |
| `account` | the AWS account to access |
| `role`    | the role to access        |

## Getting started

### Prerequisites

To use this Access Provider you'll need to have [deployed Common Fate](https://docs.commonfate.io/common-fate/next/deploying-common-fate/deploying-common-fate). You'll also need to [download the `cf` CLI](https://docs.commonfate.io/common-fate/next/providers/setup).

You will also need AWS credentials with the ability to deploy CloudFormation templates.

To use this Access Provider, you need to have AWS IAM Identity Center set up in your AWS Organization. Please [contact us via Slack](https://join.slack.com/t/commonfatecommunity/shared_invite/zt-q4m96ypu-_gYlRWD3k5rIsaSsqP7QMg) if you'd like to use this Access Provider, but are not using IAM Identity Center.

### 1. Deploy access roles

First, deploy the IAM roles below.

#### AWS SSO provisioning role

This role is used to list AWS resources including accounts, organizational units, and permission sets. It is also used to provision account assignments.

Deploy this role into the account with the log groups you wish to grant access to:

[![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://console.aws.amazon.com/cloudformation/home#/stacks/new?stackName=cf-access-common-fate-aws-aws-sso-provision&templateURL=https://common-fate-registry-public.s3.us-west-2.amazonaws.com/common-fate/aws/latest/roles/aws-sso-provision.json)

### 2. Deploy the Access Provider

To deploy this Access Provider, open a terminal window and assume an AWS role with access to deploy CloudFormation resources in the Common Fate account. Then, run:

```
cf provider deploy
```

and select the `common-fate/aws` Provider when prompted.
