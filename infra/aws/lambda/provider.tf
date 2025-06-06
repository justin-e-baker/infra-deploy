provider "aws" {
  region = var.region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

variable "aws_access_key" {
  description = "AWS Access Key"
  type = string
  sensitive = true
}

variable "aws_secret_key" {
  description = "AWS Secret Key"
  type = string
  sensitive = true
}

variable "region" {
  description = "AWS region to deploy Lambda & API gateway"
  type = string
  default = "us-east-1"
}
