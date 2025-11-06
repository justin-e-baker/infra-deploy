# ------------------------------------------------------------------
# Random suffix for unique app name
# ------------------------------------------------------------------
resource "random_string" "suffix" {
  length  = 12
  special = false
  upper   = false
}

# ------------------------------------------------------------------
# Build the final Web App name
# ------------------------------------------------------------------
locals {
final_name = var.azure_app_name != null ? var.azure_app_name : random_string.suffix.result
target     = var.redirector_target
get_paths  = var.get_path  != "" ? [trimsuffix(var.get_path,  "/")] : []  
post_paths = var.post_path != "" ? [trimsuffix(var.post_path, "/")] : []
}

# ------------------------------------------------------------------
# Resource Group
# ------------------------------------------------------------------
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

# ------------------------------------------------------------------
# App Service Plan (Linux, B1)
# ------------------------------------------------------------------
resource "azurerm_service_plan" "plan" {
  name                = "${var.resource_group_name}-plan"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  os_type             = "Linux"
  sku_name            = "B1"
}

# ------------------------------------------------------------------
# ZIP the application: app.py + requirements.txt + runtime.txt
# ------------------------------------------------------------------
data "archive_file" "app_zip" {
  type        = "zip"
  output_path = "${path.module}/app.zip"

  source {
    content  = file("${path.module}/app/app.py")
    filename = "app.py"
  }

  source {
    content  = file("${path.module}/app/requirements.txt")
    filename = "requirements.txt"
  }

  source {
    content  = file("${path.module}/app/runtime.txt")
    filename = "runtime.txt"
  }
}

# ------------------------------------------------------------------
# Linux Web App (Python 3.11)
# ------------------------------------------------------------------
resource "azurerm_linux_web_app" "proxy_app" {
  name                = local.final_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  service_plan_id     = azurerm_service_plan.plan.id

  site_config {
    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    ENCLAVE_REDIRECTOR               = var.redirector_target
    ALLOWED_GET_PATHS                = var.get_path != "" ? var.get_path : "/"
    ALLOWED_POST_PATHS               = var.post_path != "" ? var.post_path : "/"
    STARTUP_COMMAND                  = "gunicorn --bind=0.0.0.0:$PORT --workers=4 app:app"
    SCM_DO_BUILD_DURING_DEPLOYMENT   = "true"
    WEBSITES_PORT                    = "8000"
  }

  # Deploy ZIP package
  zip_deploy_file = data.archive_file.app_zip.output_path

  # Optional: Enable logging
  logs {
    http_logs {
      file_system {
        retention_in_mb   = 35
        retention_in_days = 7
      }
    }
  }
}