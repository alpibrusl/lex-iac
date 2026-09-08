terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
provider "aws" {
  region                      = "eu-west-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

resource "aws_ecs_task_definition" "api" {
  family                = "payments-api"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/payments-api"
  retention_in_days = 30
  tags = { team = "payments" }
}

resource "aws_ecs_task_definition" "worker" {
  family                = "payments-worker"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/payments-worker"
  retention_in_days = 30
  tags = { team = "payments" }
}

resource "aws_ecs_task_definition" "scheduler" {
  family                = "payments-scheduler"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "scheduler" {
  name              = "/ecs/payments-scheduler"
  retention_in_days = 30
  tags = { team = "payments" }
}

resource "aws_ecs_task_definition" "webhooks" {
  family                = "payments-webhooks"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "webhooks" {
  name              = "/ecs/payments-webhooks"
  retention_in_days = 30
  tags = { team = "payments" }
}

resource "aws_ecs_task_definition" "reports" {
  family                = "payments-reports"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "reports" {
  name              = "/ecs/payments-reports"
  retention_in_days = 30
  tags = { team = "payments" }
}

resource "aws_ecs_task_definition" "search" {
  family                = "payments-search"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "search" {
  name              = "/ecs/payments-search"
  retention_in_days = 30
  tags = { team = "payments" }
}

resource "aws_ecs_task_definition" "notify" {
  family                = "payments-notify"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "notify" {
  name              = "/ecs/payments-notify"
  retention_in_days = 30
  tags = { team = "payments" }
}

resource "aws_ecs_task_definition" "billing" {
  family                = "payments-billing"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "billing" {
  name              = "/ecs/payments-billing"
  retention_in_days = 30
  tags = { team = "payments" }
}

resource "aws_ecs_task_definition" "exporter" {
  family                = "payments-exporter"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "exporter" {
  name              = "/ecs/payments-exporter"
  retention_in_days = 30
  tags = { team = "payments" }
}

resource "aws_ecs_task_definition" "gateway" {
  family                = "payments-gateway"
  container_definitions = "[]"
  tags = { team = "payments", rev = "2026-09-08" }
}

resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/ecs/payments-gateway"
  retention_in_days = 30
  tags = { team = "payments" }
}
