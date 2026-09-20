# SecureVault Infrastructure Terraform Provisioning Configuration
terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}

# 1. VPC Configuration
resource "aws_vpc" "secure_vault_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "secure-vault-vpc"
  }
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.secure_vault_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "secure-vault-private-1"
  }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.secure_vault_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "secure-vault-private-2"
  }
}

resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "secure-vault-db-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]
}

# 2. Security Groups
resource "aws_security_group" "rds_sg" {
  name        = "secure-vault-rds-sg"
  description = "Allow inbound traffic to PostgreSQL from Lambda"
  vpc_id      = aws_vpc.secure_vault_vpc.id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Amazon RDS PostgreSQL Database
resource "aws_db_instance" "secure_vault_rds" {
  allocated_storage      = 20
  engine                 = "postgres"
  engine_version         = "15.3"
  instance_class         = "db.t3.micro"
  db_name                = "securevault"
  username               = "vault_user"
  password               = "SecureVaultPassword123!"
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  skip_final_snapshot    = true
}

# 4. AWS SNS Topic for SQL Injection Alerts
resource "aws_sns_topic" "sql_alerts" {
  name = "secure-vault-sqli-alerts"
}

# 5. AWS Lambda Function
resource "aws_iam_role" "lambda_role" {
  name = "secure_vault_lambda_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_lambda_function" "secure_vault_lambda" {
  filename      = "backend.zip"
  function_name = "SecureVaultBackend"
  role          = aws_iam_role.lambda_role.arn
  handler       = "src/lambda.handler"
  runtime       = "nodejs18.x"
  memory_size   = 512
  timeout       = 10

  environment {
    variables = {
      DB_HOST             = aws_db_instance.secure_vault_rds.endpoint
      DB_USER             = "vault_user"
      DB_PASS             = "SecureVaultPassword123!"
      KMS_KEY_ID          = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      HMAC_SECRET         = "terraform_hmac_secret_32_bytes_len!!"
      JWT_SECRET          = "terraform_jwt_secret_32_bytes_len!!"
      SNS_ALERT_TOPIC_ARN = aws_sns_topic.sql_alerts.arn
    }
  }
}

# 6. Outputs
output "rds_endpoint" {
  value = aws_db_instance.secure_vault_rds.endpoint
}

output "sns_topic_arn" {
  value = aws_sns_topic.sql_alerts.arn
}
