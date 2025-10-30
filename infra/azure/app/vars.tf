variable "location" {
  default = "westus2"
}

variable "resource_group_name" {
  default = "rg-enclave-proxy"
}

variable "enclave_redirector" {
  description = "Upstream domain to proxy to"
  type        = string
  sensitive   = true
}