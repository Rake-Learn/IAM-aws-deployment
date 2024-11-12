provider "aws" {
  region = "us-east-1"  # Set your preferred region
}

# ECS Task Execution Role
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs_task_execution_role"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ecs-tasks.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })
}

# Policy for ECS Task to Pull from ECR and Log to CloudWatch
#tfsec:ignore:aws-iam-no-policy-wildcards - Wildcard is required to allow ECS tasks logging to any log group
resource "aws_iam_policy" "ecs_task_execution_policy" {
  name = "ecs_task_execution_policy"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ],
        "Resource": "*"
      },
      #tfsec:ignore:aws-iam-no-policy-wildcards - Required wildcard for CloudWatch Logs
      {
        "Effect": "Allow",
        "Action": [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource": "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Attach ECS Task Execution Policy to the ECS Task Execution Role
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_attach" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = aws_iam_policy.ecs_task_execution_policy.arn
}

# IAM Role for Lambda (or Step Functions) to Invoke ECS Tasks
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role" "lambda_invoke_ecs_role" {
  name = "lambda_invoke_ecs_role"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      },
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "states.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })
}

# Policy to Allow Lambda or Step Functions to Run ECS Tasks
resource "aws_iam_policy" "lambda_ecs_invoke_policy" {
  name = "lambda_ecs_invoke_policy"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "ecs:RunTask",
          "ecs:DescribeTasks",
          "ecs:StopTask"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "iam:PassRole"
        ],
        "Resource": aws_iam_role.ecs_task_execution_role.arn
      }
    ]
  })
}

# Attach Lambda ECS Invoke Policy to the Lambda Role
resource "aws_iam_role_policy_attachment" "lambda_invoke_ecs_role_attach" {
  role       = aws_iam_role.lambda_invoke_ecs_role.name
  policy_arn = aws_iam_policy.lambda_ecs_invoke_policy.arn
}
# Store ECS Task Execution Role ARN in SSM Parameter Store
resource "aws_ssm_parameter" "ecs_task_execution_role_arn" {
  name        = "/my-vpc/ecs_task_execution_role_arn"
  description = "ECS Task Execution Role ARN"
  type        = "String"
  value       = aws_iam_role.ecs_task_execution_role.arn
}

# Store Lambda Invoke ECS Role ARN in SSM Parameter Store
resource "aws_ssm_parameter" "lambda_invoke_ecs_role_arn" {
  name        = "/my-vpc/lambda_invoke_ecs_role_arn"
  description = "Lambda Invoke ECS Role ARN"
  type        = "String"
  value       = aws_iam_role.lambda_invoke_ecs_role.arn
}