terraform {
  required_providers {
    aws = {
        source = hashicorp/aws
        configuration_aliases = [ aws.virginia, aws ]
    }
  }
  backend "s3" {
  profile        = "aws-main-prod"
  bucket         = "aws-main-prod-tfstate"
  key            = "tf/prod"
  dynamodb_table = "terraform-state-lock"
  region         = "eu-central-1"
  encrypt        = true
  kms_key_id     = "<kms ARN>"
}
}

provider "aws" {
    region = var.region
    profile = "aws-sec-prod" #for aws configured profile

    default_tags {
        tags = {
            Team = "Security"
            Infra = "Prod"
        }
    }
  
}