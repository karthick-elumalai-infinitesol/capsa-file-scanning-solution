# ============================================================================
# ECS Cluster
# ============================================================================

resource "aws_ecs_cluster" "main" {
  name = var.ecs_names["cluster"]
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = {
    Name        = var.ecs_names["cluster"]
    Environment = var.environment
  }
}

# ============================================================================
# CloudWatch Log Groups
# ============================================================================

resource "aws_cloudwatch_log_group" "clamav" {
  name              = var.log_group_names["clamav"]
  retention_in_days = 30
  tags = {
    Name        = var.log_group_names["clamav"]
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = var.log_group_names["worker"]
  retention_in_days = 30
  tags = {
    Name        = var.log_group_names["worker"]
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "redis" {
  name              = var.log_group_names["redis"]
  retention_in_days = 30
  tags = {
    Name        = var.log_group_names["redis"]
    Environment = var.environment
  }
}

# ============================================================================
# ClamAV Task Definition & Service
# ============================================================================

resource "aws_ecs_task_definition" "clamav" {
  family                   = var.ecs_names["task_clamav"]
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.clamav_cpu
  memory                   = var.clamav_memory
  execution_role_arn       = var.ecs_task_execution_role_arn
  task_role_arn            = var.ecs_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "clamav"
      image     = var.clamav_image
      essential = true

      portMappings = [
        {
          containerPort = var.clamav_port
          protocol      = "tcp"
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.clamav.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "clamav"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "clamdscan --version || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 5
        startPeriod = 120
      }

      systemControls = []
    },
  ])

  tags = {
    Name        = var.ecs_names["task_clamav"]
    Environment = var.environment
  }
}

resource "aws_ecs_service" "clamav" {
  name                              = var.ecs_names["service_clamav"]
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.clamav.arn
  desired_count                     = 1
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 120
  enable_execute_command            = false

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.clamav_service_sg_id]
    assign_public_ip = var.ecs_assign_public_ip
  }

  service_registries {
    registry_arn = var.service_discovery_clamav_id
  }

  tags = {
    Name        = var.ecs_names["service_clamav"]
    Environment = var.environment
  }
}

# ============================================================================
# Redis Task Definition & Service
# ============================================================================

resource "aws_ecs_task_definition" "redis" {
  family                   = var.ecs_names["task_redis"]
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.redis_cpu
  memory                   = var.redis_memory
  execution_role_arn       = var.ecs_task_execution_role_arn

  container_definitions = jsonencode([
    {
      name      = "redis"
      image     = var.redis_image
      essential = true
      user      = "999"

      portMappings = [
        {
          containerPort = 6379
          protocol      = "tcp"
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.redis.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "redis"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "redis-cli ping | grep PONG || exit 1"]
        interval    = 10
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }

      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
        }
      }

      readonlyRootFilesystem = true
    },
  ])

  tags = {
    Name        = var.ecs_names["task_redis"]
    Environment = var.environment
  }
}

resource "aws_ecs_service" "redis" {
  name                              = var.ecs_names["service_redis"]
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.redis.arn
  desired_count                     = 1
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60
  enable_execute_command            = false

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.redis_sg_id]
    assign_public_ip = var.ecs_assign_public_ip
  }

  dynamic "service_registries" {
    for_each = var.service_discovery_redis_id != "" ? [1] : []
    content {
      registry_arn = var.service_discovery_redis_id
    }
  }

  tags = {
    Name        = var.ecs_names["service_redis"]
    Environment = var.environment
  }
}

# ============================================================================
# CloudWatch Log Group for SFTPGo
# ============================================================================

resource "aws_cloudwatch_log_group" "sftpgo" {
  name              = var.log_group_names["sftpgo"]
  retention_in_days = 30
  tags = {
    Name        = var.log_group_names["sftpgo"]
    Environment = var.environment
  }
}

# ============================================================================
# SFTPGo Task Definition & Service
# ============================================================================

resource "aws_ecs_task_definition" "sftpgo" {
  family                   = var.ecs_names["task_sftpgo"]
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.sftpgo_cpu
  memory                   = var.sftpgo_memory
  execution_role_arn       = var.ecs_task_execution_role_arn
  task_role_arn            = var.sftpgo_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "sftpgo"
      image     = var.sftpgo_image
      essential = true

      portMappings = [
        {
          containerPort = 2022
          protocol      = "tcp"
        },
        {
          containerPort = 8080
          protocol      = "tcp"
        },
      ]

      environment = [
        { name = "SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN", value = "true" },
        { name = "SFTPGO_DEFAULT_ADMIN_USERNAME", value = "admin" },
        { name = "SFTPGO_SFTPD__BINDINGS__0__PORT", value = "2022" },
        { name = "SFTPGO_SFTPD__BINDINGS__0__HOST", value = "0.0.0.0" },
        { name = "SFTPGO_HTTPD__BINDINGS__0__PORT", value = "8080" },
        { name = "SFTPGO_DATA_PROVIDER__DRIVER", value = "bolt" },
        { name = "SFTPGO_DATA_PROVIDER__BOLTDB__PATH", value = "/srv/sftpgo/sftpgo.db" },
        { name = "SFTPGO_S3_PROVIDER__BUCKET", value = var.staging_bucket_name },
        { name = "SFTPGO_S3_PROVIDER__REGION", value = var.aws_region },
        { name = "SFTPGO_S3_PROVIDER__KEY_PREFIX", value = "" },
        { name = "SFTPGO_S3_PROVIDER__UPLOAD_MODE", value = "1" },
        { name = "SFTPGO_COMMON__UPLOAD_MODE", value = "2" },
        { name = "SFTPGO_COMMON__TEMP_PATH", value = "/tmp" },
        { name = "TMPDIR", value = "/tmp" },
      ]

      secrets = [
        {
          name      = "SFTPGO_DEFAULT_ADMIN_PASSWORD"
          valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:capsa/sftpgo-admin-password"
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.sftpgo.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "sftpgo"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "sftpgo ping || exit 1"]
        interval    = 15
        timeout     = 5
        retries     = 5
        startPeriod = 30
      }

      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
        }
      }

      readonlyRootFilesystem = false
    },
  ])

  tags = {
    Name        = var.ecs_names["task_sftpgo"]
    Environment = var.environment
  }
}

resource "aws_ecs_service" "sftpgo" {
  name                              = var.ecs_names["service_sftpgo"]
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.sftpgo.arn
  desired_count                     = 1
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60
  enable_execute_command            = false

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.sftpgo_sg_id]
    assign_public_ip = var.ecs_assign_public_ip
  }

  dynamic "service_registries" {
    for_each = var.service_discovery_sftpgo_id != "" ? [1] : []
    content {
      registry_arn = var.service_discovery_sftpgo_id
    }
  }

  tags = {
    Name        = var.ecs_names["service_sftpgo"]
    Environment = var.environment
  }
}

# ============================================================================
# Queue Worker Task Definition & Service
# ============================================================================

resource "aws_ecs_task_definition" "worker" {
  family                   = var.ecs_names["task_worker"]
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = var.ecs_task_execution_role_arn
  task_role_arn            = var.ecs_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "queue-worker"
      image     = var.scanner_image
      essential = true

      command = [
        "python", "scripts/queue_worker.py",
        "--batch-size", "50",
        "--poll-interval", "5",
      ]

      environment = [
        { name = "QUEUE_BACKEND", value = "redis" },
        { name = "REDIS_URL", value = "redis://${var.redis_dns_name}:6379/0" },
        { name = "CLAMAV_HOST", value = var.clamav_dns_name },
        { name = "CLAMAV_PORT", value = tostring(var.clamav_port) },
        { name = "CLAMAV_TIMEOUT", value = "30" },
        { name = "LOG_LEVEL", value = "INFO" },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "ROUTING_FUNCTION_NAME", value = var.routing_function_name },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.worker.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "worker"
        }
      }

      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
        }
      }

      readonlyRootFilesystem = true
    },
  ])

  tags = {
    Name        = var.ecs_names["task_worker"]
    Environment = var.environment
  }
}

resource "aws_ecs_service" "worker" {
  name                              = var.ecs_names["service_worker"]
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.worker.arn
  desired_count                     = 1
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60
  enable_execute_command            = false

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.clamav_service_sg_id]
    assign_public_ip = var.ecs_assign_public_ip
  }

  depends_on = [
    aws_ecs_service.clamav,
    aws_ecs_service.redis,
  ]

  tags = {
    Name        = var.ecs_names["service_worker"]
    Environment = var.environment
  }
}

# ============================================================================
# Outputs
# ============================================================================

output "cluster_id" {
  value       = aws_ecs_cluster.main.id
  description = "ECS cluster ID"
}

output "cluster_name" {
  value       = aws_ecs_cluster.main.name
  description = "ECS cluster name"
}

output "cluster_arn" {
  value       = aws_ecs_cluster.main.arn
  description = "ECS cluster ARN"
}

output "clamav_task_definition_arn" {
  value       = aws_ecs_task_definition.clamav.arn
  description = "ClamAV task definition ARN"
}

output "sftpgo_task_definition_arn" {
  value       = aws_ecs_task_definition.sftpgo.arn
  description = "SFTPGo task definition ARN"
}
