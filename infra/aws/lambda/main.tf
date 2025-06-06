# Create an IAM role for Lambda to assume
resource "aws_iam_role" "lambda_exec" {
  name = "lambda_exec_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"  # Lambda can assume this role
      }
    }]
  })
}

# Attach AWS-managed policy to allow Lambda to write logs to CloudWatch
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Package the Lambda function Python code into a .zip archive
data "archive_file" "lambda_zip" {
  type = "zip"
  source_dir = "${path.module}/lambda_function"  # Folder with main.py
  output_path = "${path.module}/lambda_function.zip"
}

# Upload the dependencies.zip file as a Lambda layer
resource "aws_lambda_layer_version" "dependencies_layer" {
  filename          = "${path.module}/dependencies.zip"
  layer_name        = "dependencies-layer"
  source_code_hash  = filebase64sha256("${path.module}/dependencies.zip")
}


# Create the Lambda function
resource "aws_lambda_function" "forwarder" {
  function_name = "traffic_forwarder"
  filename = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  handler = "lambda.lambda_handler"
  runtime = "python3.10"         # Your desired runtime
  role = aws_iam_role.lambda_exec.arn
  architectures = ["x86_64"]     # Architecture compatibility

  environment {
    variables = {
      REDIRECTOR_TARGET = var.redirector_target
    }
  }
  
  # Attach the requests layer
  layers = [
    aws_lambda_layer_version.dependencies_layer.arn
  ]
}

# Create an HTTP API Gateway (v2) to expose the Lambda function via HTTP
resource "aws_apigatewayv2_api" "http_api" {
  name          = "lambda-forward-api"
  protocol_type = "HTTP"
}

# Connect API Gateway to Lambda using AWS_PROXY integration
resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id             = aws_apigatewayv2_api.http_api.id
  integration_type   = "AWS_PROXY"  # Pass entire HTTP request directly
  integration_uri    = aws_lambda_function.forwarder.invoke_arn
  integration_method = "POST"
  payload_format_version = "2.0"
}

# Define a route that forwards all traffic (ANY method and any path) to Lambda
resource "aws_apigatewayv2_route" "default_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "ANY /{proxy+}"  # Matches all paths
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

# Enable auto-deployment of the API
resource "aws_apigatewayv2_stage" "default_stage" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"  # Special stage that doesn't require a custom path
  auto_deploy = true
}

# Grant API Gateway permission to invoke the Lambda function
resource "aws_lambda_permission" "allow_apigw" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.forwarder.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}