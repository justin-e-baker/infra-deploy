variable "cdn_endpoint_name" {
  description = "Name for the CDN endpoint"
  type        = string
  default     = "my-frontdoor-endpoint"  # fallback default
}

variable "custom_domain_name" {
  description = "The custom domain name to map (e.g., cdn.yourdomain.com)"
  type        = string
}

variable "origin_hostname" {
  description = "The custom origin hostname for the CDN endpoint (Domain pointing to redirector)"
  type        = string
}

variable "origin_host_header" {
  description = "The host header to send to the custom origin"
  type        = string
}

