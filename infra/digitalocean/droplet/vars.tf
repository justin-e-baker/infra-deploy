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

