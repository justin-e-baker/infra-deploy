resource "random_string" "suffix" {
  length  = 12
  special = false
  upper   = false
  lower   = true
}

locals {
  name       = var.distribution_name != null ? var.distribution_name : "${random_string.suffix.result}"
  target     = var.redirector_target
  get_paths  = var.get_path  != "" ? [trimsuffix(var.get_path,  "/")] : ["*"]
  post_paths = var.post_path != "" ? [trimsuffix(var.post_path, "/")] : ["*"]
}

resource "aws_cloudfront_response_headers_policy" "deny" {
  name = "deny-${local.name}"

  security_headers_config {
    content_type_options { override = true }
    frame_options {
      override     = true
      frame_option = "DENY"
    }
    referrer_policy {
      override        = true
      referrer_policy = "no-referrer"
    }
    xss_protection {
      override   = true
      protection = true
      mode_block = true
    }
    strict_transport_security {
      override                   = true
      include_subdomains         = true
      preload                    = true
      access_control_max_age_sec = 31536000
    }
  }
}

resource "aws_cloudfront_distribution" "proxy" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "Redirector ${local.name}"
  price_class     = "PriceClass_All"

  origin {
    domain_name = local.target
    origin_id   = "origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  dynamic "ordered_cache_behavior" {
    for_each = local.post_paths
    content {
      path_pattern           = "/${ordered_cache_behavior.value}*"
      target_origin_id       = "origin"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"]
      cached_methods         = ["GET","HEAD"]
      forwarded_values {
        query_string = true
        headers      = ["*"]
        cookies { forward = "all" }
      }
      min_ttl     = 0
      default_ttl = 0
      max_ttl     = 0
    }
  }

  dynamic "ordered_cache_behavior" {
    for_each = local.get_paths
    content {
      path_pattern           = "/${ordered_cache_behavior.value}*"
      target_origin_id       = "origin"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET","HEAD","OPTIONS"]
      cached_methods         = ["GET","HEAD"]
      forwarded_values {
        query_string = true
        headers      = ["*"]
        cookies { forward = "all" }
      }
      min_ttl     = 0
      default_ttl = 0
      max_ttl     = 0
    }
  }

  default_cache_behavior {
    target_origin_id           = "origin"
    viewer_protocol_policy     = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.deny.id
    allowed_methods = ["GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE"]
    cached_methods             = ["GET","HEAD"]
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
	compress = false
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = { Name = "redirector-${local.name}" }
}

output "cloudfront_url" {
  value = aws_cloudfront_distribution.proxy.domain_name
}
