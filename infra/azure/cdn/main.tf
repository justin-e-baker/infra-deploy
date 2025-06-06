# Create a resource group
resource "azurerm_resource_group" "rg" {
  name     = "cdn-frontdoor-rg"
  location = "eastus"
}

# Create a CDN profile with Standard_Microsoft SKU
resource "azurerm_cdn_profile" "cdn_profile" {
  name                = "my-frontdoor-profile"
  location            = "Global"
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard_Microsoft"
}

# Create a CDN endpoint with custom origin
resource "azurerm_cdn_endpoint" "cdn_endpoint" {
  name                = var.cdn_endpoint_name
  profile_name        = azurerm_cdn_profile.cdn_profile.name
  resource_group_name = azurerm_resource_group.rg.name
  location            = "Global"

  origin {
    name      = "custom-origin"
    host_name = var.origin_hostname
  }

  is_compression_enabled         = false
  querystring_caching_behaviour = "IgnoreQueryString"
}

# Map a custom domain to the CDN endpoint
resource "azurerm_cdn_endpoint_custom_domain" "cdn_custom_domain" {
  name            = "custom-domain"
  cdn_endpoint_id = azurerm_cdn_endpoint.cdn_endpoint.id
  host_name       = var.custom_domain_name

  cdn_managed_https {
    certificate_type            = "Dedicated"
    protocol_type                 = "ServerNameIndication"
    tls_version           = "TLS12"
  }
}
