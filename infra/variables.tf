// infra/variables.tf

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "bucket_name" {
  type        = string
  description = "S3 bucket for hosting the static site"
}

variable "domain_name" {
  type        = string
  description = "Your custom domain, e.g. youmightwanna.org"
}

variable "route53_zone_id" {
  type        = string
  description = "Route 53 Hosted Zone ID for your domain"
}

variable "acm_certificate_arn" {
  type        = string
  description = "ARN of an ACM certificate in us-east-1 covering your domain"
}
