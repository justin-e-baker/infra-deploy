variable "admin_username" {
  description = "Username for admin user"
  type        = string
  default = "admin-user"
}

variable "get_path" {
  type    = string
  description = "Path for GET requests (e.g., /health)"
}

variable "post_path" {
  type    = string
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
  
variable "pvt_key" {
  description = "Private key path for SSH access"
  type        = string
  default     = ""
}