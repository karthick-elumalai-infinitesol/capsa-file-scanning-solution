data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = length(var.subnet_ids) == 0 ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

data "aws_subnet" "selected" {
  count = length(var.subnet_ids) > 0 ? length(var.subnet_ids) : 0
  id    = length(var.subnet_ids) > 0 ? var.subnet_ids[count.index] : data.aws_subnets.default[0].ids[count.index % length(data.aws_subnets.default[0].ids)]
}

data "aws_region" "current" {}

data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.name}.s3"
}

locals {
  vpc_id     = var.vpc_id == "" ? data.aws_vpc.default[0].id : var.vpc_id
  subnet_ids = length(var.subnet_ids) > 0 ? var.subnet_ids : data.aws_subnets.default[0].ids
}

# ── Security Groups ────────────────────────────────────────────────────────

resource "aws_security_group" "clamav_service" {
  name_prefix = "capsa-clamav-sg-"
  description = "Security group for ClamAV ECS service"
  vpc_id      = local.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name        = "capsa-clamav-service-sg"
    Environment = var.environment
  }
}

resource "aws_security_group" "lambda_to_clamav" {
  name_prefix = "capsa-lambda-clamav-sg-"
  description = "Security group for Lambda-to-ClamAV traffic"
  vpc_id      = local.vpc_id

  tags = {
    Name        = "capsa-lambda-clamav-sg"
    Environment = var.environment
  }
}

# Break circular dep by using aws_security_group_rule for cross-references
resource "aws_security_group_rule" "clamav_ingress" {
  type                     = "ingress"
  from_port                = var.clamav_port
  to_port                  = var.clamav_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.lambda_to_clamav.id
  security_group_id        = aws_security_group.clamav_service.id
  description              = "ClamAV port from Lambda SG"
}

resource "aws_security_group_rule" "clamav_ingress_from_worker" {
  type                     = "ingress"
  from_port                = var.clamav_port
  to_port                  = var.clamav_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.clamav_service.id
  security_group_id        = aws_security_group.clamav_service.id
  description              = "ClamAV port from ECS worker SG"
}

resource "aws_security_group_rule" "lambda_egress" {
  type                     = "egress"
  from_port                = var.clamav_port
  to_port                  = var.clamav_port
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.clamav_service.id
  security_group_id        = aws_security_group.lambda_to_clamav.id
  description              = "Outbound to ClamAV service"
}

resource "aws_security_group_rule" "lambda_redis_egress" {
  type                     = "egress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.redis_service.id
  security_group_id        = aws_security_group.lambda_to_clamav.id
  description              = "Outbound to Redis service"
}

resource "aws_security_group" "redis_service" {
  name_prefix = "capsa-redis-sg-"
  description = "Security group for Redis in ECS"
  vpc_id      = local.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda_to_clamav.id, aws_security_group.clamav_service.id]
    description     = "Redis from Lambda and ECS worker SGs"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name        = "capsa-redis-service-sg"
    Environment = var.environment
  }
}

# ── Private AWS Service Access (VPC Endpoints) ──────────────────────────────
# Keeps CAPSA scan/routing/reporting workloads private while allowing access to
# required AWS APIs without relying on public internet paths.

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "capsa-vpc-endpoints-sg-"
  description = "Security group for CAPSA AWS interface VPC endpoints"
  vpc_id      = local.vpc_id

  tags = {
    Name        = "capsa-vpc-endpoints-sg"
    Environment = var.environment
  }
}

resource "aws_security_group_rule" "vpc_endpoints_ingress_from_lambda" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.lambda_to_clamav.id
  security_group_id        = aws_security_group.vpc_endpoints.id
  description              = "HTTPS from Lambda functions to AWS PrivateLink endpoints"
}

resource "aws_security_group_rule" "vpc_endpoints_ingress_from_ecs" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.clamav_service.id
  security_group_id        = aws_security_group.vpc_endpoints.id
  description              = "HTTPS from ECS tasks to AWS PrivateLink endpoints"
}

resource "aws_security_group_rule" "vpc_endpoints_ingress_from_redis" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.redis_service.id
  security_group_id        = aws_security_group.vpc_endpoints.id
  description              = "HTTPS from Redis ECS task to AWS PrivateLink endpoints"
}

resource "aws_security_group_rule" "vpc_endpoints_ingress_from_sftpgo" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.sftpgo_service.id
  security_group_id        = aws_security_group.vpc_endpoints.id
  description              = "HTTPS from SFTPGo ECS task to AWS PrivateLink endpoints"
}

resource "aws_security_group_rule" "redis_endpoint_https_egress" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vpc_endpoints.id
  security_group_id        = aws_security_group.redis_service.id
  description              = "Outbound HTTPS from Redis ECS task to AWS PrivateLink endpoints"
}

resource "aws_security_group_rule" "sftpgo_endpoint_https_egress" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vpc_endpoints.id
  security_group_id        = aws_security_group.sftpgo_service.id
  description              = "Outbound HTTPS from SFTPGo ECS task to AWS PrivateLink endpoints"
}

resource "aws_security_group_rule" "vpc_endpoints_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.vpc_endpoints.id
  description       = "Endpoint ENI response traffic"
}

resource "aws_security_group_rule" "lambda_endpoint_https_egress" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vpc_endpoints.id
  security_group_id        = aws_security_group.lambda_to_clamav.id
  description              = "Outbound HTTPS from Lambda functions to AWS PrivateLink endpoints"
}

resource "aws_security_group_rule" "ecs_endpoint_https_egress" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vpc_endpoints.id
  security_group_id        = aws_security_group.clamav_service.id
  description              = "Outbound HTTPS from ECS tasks to AWS PrivateLink endpoints"
}

resource "aws_security_group_rule" "lambda_s3_gateway_egress" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  prefix_list_ids   = [data.aws_prefix_list.s3.id]
  security_group_id = aws_security_group.lambda_to_clamav.id
  description       = "Outbound HTTPS from Lambda functions to S3 Gateway endpoint prefix list"
}

resource "aws_security_group_rule" "ecs_s3_gateway_egress" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  prefix_list_ids   = [data.aws_prefix_list.s3.id]
  security_group_id = aws_security_group.clamav_service.id
  description       = "Outbound HTTPS from ECS tasks to S3 Gateway endpoint prefix list"
}

resource "aws_vpc_endpoint" "s3" {
  count             = length(var.route_table_ids) > 0 ? 1 : 0
  vpc_id            = local.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.route_table_ids

  tags = {
    Name        = "capsa-${var.environment}-s3-endpoint"
    Environment = var.environment
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset([
    "sns",
    "logs",
    "monitoring",
    "kms",
    "secretsmanager",
    "ecr.api",
    "ecr.dkr",
    "lambda",
    "sts",
  ])

  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.subnet_ids
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name        = "capsa-${var.environment}-${replace(each.value, ".", "-")}-endpoint"
    Environment = var.environment
  }
}

# ── Service Discovery ──────────────────────────────────────────────────────

resource "aws_service_discovery_private_dns_namespace" "capsa" {
  name        = var.service_discovery_namespace
  description = "Private DNS namespace for CAPSA internal services"
  vpc         = local.vpc_id
}

resource "aws_service_discovery_service" "redis" {
  name = "redis"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.capsa.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_security_group" "sftpgo_service" {
  name_prefix = "capsa-sftpgo-sg-"
  description = "Security group for SFTPGo ECS service"
  vpc_id      = local.vpc_id

  ingress {
    from_port   = var.sftpgo_port
    to_port     = var.sftpgo_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SFTP from internet"
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.vpc_id == "" ? ["0.0.0.0/0"] : []
    description = "SFTPGo REST API (internal only in production)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name        = "capsa-sftpgo-service-sg"
    Environment = var.environment
  }
}

resource "aws_service_discovery_service" "sftpgo" {
  name = "sftpgo"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.capsa.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_service_discovery_service" "clamav" {
  name = "clamav"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.capsa.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}
