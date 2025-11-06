variable "redirector_target" {
  description = "Domain to forward requests to"
  type        = string
}

variable "get_path" {
  type        = string
  description = "Path to forward GET requests"
  default     = "/"
}

variable "post_path" {
  type        = string
  description = "Path to forward POST requests"
  default     = "/"
}