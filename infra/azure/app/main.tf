# Random name
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

locals {
  app_name_final = "proxy-${random_string.suffix.result}"
}

# Resource Group
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

# App Service Plan
resource "azurerm_service_plan" "plan" {
  name                = "${local.app_name_final}-plan"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  os_type             = "Linux"
  sku_name            = "B1"  # or D1/F1

  depends_on = [azurerm_resource_group.rg]
}

# Package files
data "archive_file" "app_zip" {
  type        = "zip"
  output_path = "${path.module}/nginx-proxy.zip"

  source {
    content  = file("${path.module}/app/nginx.conf")
    filename = "nginx.conf"
  }
  source {
    content  = file("${path.module}/app/default.conf.template")
    filename = "default.conf.template"
  }
  source {
    content  = file("${path.module}/app/entrypoint.sh")
    filename = "entrypoint.sh"
  }
}

# Linux Web App – NGINX on 443
resource "azurerm_linux_web_app" "app" {
  name                = local.app_name_final
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  service_plan_id     = azurerm_service_plan.plan.id

  # HTTPS only
  https_only = true

  site_config {
    always_on        = true
    linux_fx_version = "NGINX|1.28"

    # CRITICAL: Listen on 443
    http2_enabled = true
    application_stack {
      # No stack – ZIP deploy
    }
  }

  app_settings = {
    "ENCLAVE_REDIRECTOR"       = var.enclave_redirector
    "WEBSITE_RUN_FROM_PACKAGE" = "1"
    "STARTUP_COMMAND"          = "/bin/sh /home/site/wwwroot/entrypoint.sh"
    # Force NGINX to use 443
    "WEBSITES_PORT"            = "443"
  }

  zip_deploy_file = data.archive_file.app_zip.output_path

  depends_on = [
    azurerm_service_plan.plan,
    data.archive_file.app_zip
  ]
}