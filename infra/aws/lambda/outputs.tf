# Display the public endpoint of the deployed API Gateway
output "api_endpoint" {
  description = "Public endpoint to call your forwarding Lambda"
  value       = aws_apigatewayv2_api.http_api.api_endpoint
}