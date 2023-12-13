# AWS Infrastructure Bootstrap with Terraform

This repository contains Terraform code for bootstrapping infrastructure on AWS. It's designed to set up various managed services, an EKS cluster, and other services.

## Disclaimer

I must emphasize that due to time constraints and the complexity of the infrastructure involved, this Terraform code represents an example of how I would structure and manage my Terraform configurations. 

Terraform can become quite complex, especially when implementing a layered approach for sophisticated systems. Therefore, it's assumed that the overall structure, TF linting rules, and best practices are determined and enforced by an SRE team to ensure consistency and maintainability across the infrastructure codebase.

## Prerequisites

To effectively use this code, developer will need to:

1. Install and configure AWS binaries for AWS access. AWS Profiles must be configured with correct aws accounts and SSO session parameters.
2. Authenticate to the target AWS account via an Identity Provider (IDP) to ensure secure and controlled access.

## Usage Instructions

Follow this standard workflow to use the Terraform code:

1. Initialize the Terraform environment with `terraform init`, which will download the required providers and modules.
2. Generate an execution plan with `terraform plan` to review the changes Terraform will execute on your AWS infrastructure.
3. Apply the configuration with `terraform apply`. This step will create the resources as defined in the Terraform files.

**Note**: In a production setting, it's advisable to use a Continuous Deployment (CD) system for the application of infrastructure changes, rather than manual execution.

## Outputs

Upon the completion of `terraform apply`, the terminal will display outputs with usefull information about the infrastructure, such as the CloudFront distribution URL, EKS version, certificates expiration dates and etc.
