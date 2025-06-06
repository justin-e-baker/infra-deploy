output "cdn_endpoint_hostname" {
  description = "Hostname of the deployed CDN endpoint"
  value = azurerm_cdn_endpoint_custom_domain.cdn_custom_domain.host_name
}