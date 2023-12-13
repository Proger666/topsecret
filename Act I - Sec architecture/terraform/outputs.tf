output "eks_version" {
  description = "The version of the EKS cluster"
  value       = aws_eks_cluster.my_cluster.version
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.secure_vpc.cidr_block
}

output "cloudfront_url" {
  description = "The URL of the CloudFront distribution"
  value       = module.cloudfront.domain_name
}

... rest outputs ... 