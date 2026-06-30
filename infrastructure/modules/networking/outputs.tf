output "vpc_id" {
  value       = local.vpc_id
  description = "VPC ID used for all deployments"
}

output "subnet_ids" {
  value       = local.subnet_ids
  description = "List of subnet IDs for Lambda and ECS"
}

output "clamav_lambda_sg_id" {
  value       = aws_security_group.lambda_to_clamav.id
  description = "Security group ID for Lambda-to-ClamAV traffic"
}

output "clamav_service_sg_id" {
  value       = aws_security_group.clamav_service.id
  description = "Security group ID for ClamAV service"
}

output "redis_sg_id" {
  value       = aws_security_group.redis_service.id
  description = "Security group ID for Redis service"
}

output "service_discovery_namespace_id" {
  value       = aws_service_discovery_private_dns_namespace.capsa.id
  description = "Service discovery namespace ID"
}

output "service_discovery_redis_id" {
  value       = aws_service_discovery_service.redis.arn
  description = "Service discovery service ARN for Redis"
}

output "redis_dns_name" {
  value       = "${aws_service_discovery_service.redis.name}.${aws_service_discovery_private_dns_namespace.capsa.name}"
  description = "DNS name for Redis service discovery"
}

output "service_discovery_clamav_id" {
  value       = aws_service_discovery_service.clamav.arn
  description = "Service discovery service ARN for ClamAV"
}

output "clamav_dns_name" {
  value       = "${aws_service_discovery_service.clamav.name}.${aws_service_discovery_private_dns_namespace.capsa.name}"
  description = "DNS name for ClamAV service discovery"
}

output "security_group_ids" {
  value       = concat([aws_security_group.lambda_to_clamav.id], var.security_group_ids)
  description = "Complete list of security group IDs for Lambda functions"
}

output "s3_vpc_endpoint_id" {
  value       = length(aws_vpc_endpoint.s3) > 0 ? aws_vpc_endpoint.s3[0].id : ""
  description = "S3 Gateway VPC endpoint ID"
}

output "interface_vpc_endpoint_ids" {
  value       = { for name, endpoint in aws_vpc_endpoint.interface : name => endpoint.id }
  description = "Interface VPC endpoint IDs by AWS service name"
}
