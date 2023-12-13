variable "region" {
  description = "The AWS region to create resources in."
  type        = string
  default     = "us-west-2"
}


variable "route53_configuration" {
  type = list(object({
    aws_route53_zone_name         = string
    aws_route53_zone_id           = string
  }))

  default = []
}