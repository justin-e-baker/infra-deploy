variable "get_path" {
  type    = string
  default = "/"
  description = "Path for GET requests (e.g., /health)"
}

variable "post_path" {
  type    = string
  default = "/"
  description = "Path for POST requests (e.g., /submit)"
}

# Existing vars (e.g., for domain/target if passed separately)
variable "resource_domain" { 
  type = string 
  default = "" 
}
variable "redirect_to" { 
  type = string 
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
  description = "AWS region"
  type = string
  default = "us-east-1"
}

variable "pvt_key" {
  description = "path to SSH private key"
}