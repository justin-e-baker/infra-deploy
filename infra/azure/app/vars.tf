variable "location" {
  default = "westus2"
}

variable "resource_group_name" {
  default = "rg-enclave-proxy"
}

variable "redirector_target" {
  description = "Where traffic goes (--redirect-to)"
  type        = string
}

variable "azure_app_name" {
  description = "(Optional) Name of Azure web app. Must be globally unique"
  type        = string
  default     = null
}
variable "get_path" {
  type    = string
  default = ""
}

variable "post_path" {
  type    = string
  default = ""
}
