# =============================================
# FINAL, BULLET-PROOF VARIABLES.TF
# =============================================
variable "redirector_target" {
  description = "Where traffic goes (--redirect-to)"
  type        = string
}

variable "get_path" {
  type = string
}

variable "post_path" {
  type = string
}

variable "distribution_name" {
  type    = string
  default = null
}

variable "aws_access_key" {
  type      = string
  sensitive = true
}
variable "aws_secret_key" {
  type      = string
  sensitive = true
}
variable "aws_region" {
  type    = string
  default = "us-east-1"
}