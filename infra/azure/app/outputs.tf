output "proxy_app_url" {
  value = "https://${azurerm_linux_web_app.proxy_app.default_hostname}"
}

output "proxy_app_name" {
  value = azurerm_linux_web_app.proxy_app.name
}
