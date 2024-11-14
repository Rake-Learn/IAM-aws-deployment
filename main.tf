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
# tfsec:ignore:aws-iam-no-policy-wildcards
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

# IAM Role for Redshift
resource "aws_iam_role" "redshift_role" {
  name = "redshift-custom-role"
  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "redshift.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })
}

# IAM Policy for Redshift with the specified actions
# tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_policy" "redshift_policy" {
  name        = "RedshiftCustomPolicy"
  description = "Custom policy for Redshift with multiple service permissions"
  policy      = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "sagemaker:CreateTrainingJob",
          "sagemaker:CreateAutoMLJob",
          "sagemaker:CreateCompilationJob",
          "sagemaker:CreateEndpoint",
          "sagemaker:DescribeAutoMLJob",
          "sagemaker:DescribeTrainingJob",
          "sagemaker:DescribeCompilationJob",
          "sagemaker:DescribeProcessingJob",
          "sagemaker:DescribeTransformJob",
          "sagemaker:ListCandidatesForAutoMLJob",
          "sagemaker:StopAutoMLJob",
          "sagemaker:StopCompilationJob",
          "sagemaker:StopTrainingJob",
          "sagemaker:DescribeEndpoint",
          "sagemaker:InvokeEndpoint",
          "sagemaker:StopProcessingJob",
          "sagemaker:CreateModel",
          "sagemaker:CreateProcessingJob"
        ],
        "Resource": [
          "arn:aws:sagemaker:*:*:model/*redshift*",
          "arn:aws:sagemaker:*:*:training-job/*redshift*",
          "arn:aws:sagemaker:*:*:automl-job/*redshift*",
          "arn:aws:sagemaker:*:*:compilation-job/*redshift*",
          "arn:aws:sagemaker:*:*:processing-job/*redshift*",
          "arn:aws:sagemaker:*:*:transform-job/*redshift*",
          "arn:aws:sagemaker:*:*:endpoint/*redshift*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents"
        ],
        "Resource": [
          "arn:aws:logs:*:*:log-group:/aws/sagemaker/Endpoints/*redshift*",
          "arn:aws:logs:*:*:log-group:/aws/sagemaker/ProcessingJobs/*redshift*",
          "arn:aws:logs:*:*:log-group:/aws/sagemaker/TrainingJobs/*redshift*",
          "arn:aws:logs:*:*:log-group:/aws/sagemaker/TransformJobs/*redshift*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "cloudwatch:PutMetricData"
        ],
        "Resource": "*",
        "Condition": {
          "StringEquals": {
            "cloudwatch:namespace": [
              "SageMaker",
              "/aws/sagemaker/Endpoints",
              "/aws/sagemaker/ProcessingJobs",
              "/aws/sagemaker/TrainingJobs",
              "/aws/sagemaker/TransformJobs"
            ]
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetAuthorizationToken",
          "ecr:GetDownloadUrlForLayer"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "s3:GetObject",
          "s3:GetBucketAcl",
          "s3:GetBucketCors",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketLocation",
          "s3:ListBucket",
          "s3:ListAllMyBuckets",
          "s3:ListMultipartUploadParts",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject",
          "s3:PutBucketAcl",
          "s3:PutBucketCors",
          "s3:DeleteObject",
          "s3:AbortMultipartUpload",
          "s3:CreateBucket"
        ],
        "Resource": [
          "arn:aws:s3:::redshift-downloads",
          "arn:aws:s3:::redshift-downloads/*",
          "arn:aws:s3:::*redshift*",
          "arn:aws:s3:::*redshift*/*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "s3:GetObject"
        ],
        "Resource": "*",
        "Condition": {
          "StringEqualsIgnoreCase": {
            "s3:ExistingObjectTag/Redshift": "true"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "dynamodb:Scan",
          "dynamodb:DescribeTable",
          "dynamodb:GetItem"
        ],
        "Resource": [
          "arn:aws:dynamodb:*:*:table/*redshift*",
          "arn:aws:dynamodb:*:*:table/*redshift*/index/*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticmapreduce:ListInstances"
        ],
        "Resource": [
          "arn:aws:elasticmapreduce:*:*:cluster/*redshift*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "elasticmapreduce:ListInstances"
        ],
        "Resource": "*",
        "Condition": {
          "StringEqualsIgnoreCase": {
            "elasticmapreduce:ResourceTag/Redshift": "true"
          }
        }
      },
      {
        "Effect": "Allow",
        "Action": [
          "lambda:InvokeFunction"
        ],
        "Resource": "arn:aws:lambda:*:*:function:*redshift*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "glue:CreateDatabase",
          "glue:DeleteDatabase",
          "glue:GetDatabase",
          "glue:GetDatabases",
          "glue:UpdateDatabase",
          "glue:CreateTable",
          "glue:DeleteTable",
          "glue:BatchDeleteTable",
          "glue:UpdateTable",
          "glue:GetTable",
          "glue:GetTables",
          "glue:BatchCreatePartition",
          "glue:CreatePartition",
          "glue:DeletePartition",
          "glue:BatchDeletePartition",
          "glue:UpdatePartition",
          "glue:GetPartition",
          "glue:GetPartitions",
          "glue:BatchGetPartition"
        ],
        "Resource": [
          "arn:aws:glue:*:*:table/*redshift*/*",
          "arn:aws:glue:*:*:catalog",
          "arn:aws:glue:*:*:database/*redshift*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecretVersionIds"
        ],
        "Resource": [
          "arn:aws:secretsmanager:*:*:secret:*redshift*"
        ]
      },
      {
        "Effect": "Allow",
        "Action": [
          "secretsmanager:GetRandomPassword",
          "secretsmanager:ListSecrets"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "iam:PassRole"
        ],
        "Resource": "arn:aws:iam::*:role/*",
        "Condition": {
          "StringEquals": {
            "iam:PassedToService": [
              "redshift.amazonaws.com",
              "glue.amazonaws.com",
              "sagemaker.amazonaws.com",
              "athena.amazonaws.com"
            ]
          }
        }
      }
    ]
  })
}

# Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "attach_redshift_policy" {
  role       = aws_iam_role.redshift_role.name
  policy_arn = aws_iam_policy.redshift_policy.arn
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

# Store RedshiftRole ARN in SSM Parameter Store
resource "aws_ssm_parameter" "Redshift_access_role" {
  name        = "/my-redshift/access_to_everything_role_arn"
  description = "Redshift access Role ARN"
  type        = "String"
  value       = aws_iam_role.redshift_role.arn
}