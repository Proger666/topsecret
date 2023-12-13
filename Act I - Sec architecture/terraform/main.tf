module "vpc" {
    source = "../module/vpc"

    vpc_name = "secure-app"
    cidr_block = "10.60.0.0/16"

    enable_dns_hostnames = true
    enable_dns_support = true

    ipv6 = true

    enable_nacl = true
    
    vpc_tags = {
        Env = "prod"
    }

    vpc_public_subnet_tags = {
     "kubernetes.io/role/elb"                = "1"
     "kubernetes.io/cluster/secure-app-prod" = "shared"
    }

    public_subnets = { ... }
    private_subnets = { ... }

  
}

module "waf" {
    source = "../module/waf"

    waf_acls = ["AWS-AWSManagedRulesBotControlRulesSet", "AWS-AWSManagedRulesIpReputationList"]

    ... rest variables ..
}

module "certificate" {
    source = "../modules/certificate/"
    domain_name = var.route53_configuration.aws_route53_zone_name
    zone_id = var.route53_configuration.aws_route53_zone_id
  
}

... rest modules ... 

