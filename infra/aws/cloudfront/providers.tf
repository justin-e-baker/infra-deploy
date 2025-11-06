# ──────────────────────────────────────────────────────────────────────
# Default provider – uses the region you pass (usually us-east-1)
# ──────────────────────────────────────────────────────────────────────
provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

# ──────────────────────────────────────────────────────────────────────
# Aliased provider – ALWAYS us-east-1 (required for CloudFront)
# ──────────────────────────────────────────────────────────────────────
provider "aws" {
  alias      = "us_east_1"
  region     = "us-east-1"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}