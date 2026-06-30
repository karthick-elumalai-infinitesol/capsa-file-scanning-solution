#!/bin/bash
# CAPSA Healthcare - Deployment Script
# Deploy infrastructure to AWS using Terraform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$PROJECT_ROOT/infrastructure"
ENVIRONMENT="${1:-prod}"
ACTION="${2:-plan}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}CAPSA Healthcare - Deployment Script${NC}"
echo -e "${GREEN}========================================${NC}"

# Check prerequisites
check_prerequisites() {
    echo -e "\n${YELLOW}Checking prerequisites...${NC}"

    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        echo -e "${RED}❌ Terraform is not installed${NC}"
        echo "Install from: https://www.terraform.io/downloads.html"
        exit 1
    fi

    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}❌ AWS CLI is not installed${NC}"
        echo "Install from: https://aws.amazon.com/cli/"
        exit 1
    fi

    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}❌ AWS credentials not configured${NC}"
        echo "Run: aws configure"
        exit 1
    fi

    echo -e "${GREEN}✅ All prerequisites met${NC}"
}

# Validate configuration
validate_config() {
    echo -e "\n${YELLOW}Validating configuration...${NC}"

    if [ ! -f "$TERRAFORM_DIR/terraform.tfvars" ]; then
        echo -e "${RED}❌ terraform.tfvars not found${NC}"
        echo "Copy from terraform.tfvars.example and fill in your values:"
        echo "  cp $TERRAFORM_DIR/terraform.tfvars.example $TERRAFORM_DIR/terraform.tfvars"
        exit 1
    fi

    # Validate tfvars
    if grep -q "your-" "$TERRAFORM_DIR/terraform.tfvars"; then
        echo -e "${RED}⚠️  terraform.tfvars contains placeholder values${NC}"
        echo "Please update the following values:"
        grep "your-" "$TERRAFORM_DIR/terraform.tfvars"
        exit 1
    fi

    echo -e "${GREEN}✅ Configuration validated${NC}"
}

# Initialize Terraform
init_terraform() {
    echo -e "\n${YELLOW}Initializing Terraform...${NC}"

    cd "$TERRAFORM_DIR"

    terraform init \
        -upgrade \
        -no-color

    echo -e "${GREEN}✅ Terraform initialized${NC}"
}

# Validate Terraform
validate_terraform() {
    echo -e "\n${YELLOW}Validating Terraform configuration...${NC}"

    cd "$TERRAFORM_DIR"

    terraform validate

    echo -e "${GREEN}✅ Terraform configuration valid${NC}"
}

# Plan Terraform changes
plan_terraform() {
    echo -e "\n${YELLOW}Planning Terraform changes...${NC}"

    cd "$TERRAFORM_DIR"

    terraform plan \
        -out=tfplan \
        -no-color

    echo -e "${GREEN}✅ Plan complete - review above and run:${NC}"
    echo "  ./scripts/deploy.sh $ENVIRONMENT apply"
}

# Apply Terraform changes
apply_terraform() {
    echo -e "\n${YELLOW}Applying Terraform changes (this may take 5-10 minutes)...${NC}"

    cd "$TERRAFORM_DIR"

    if [ -f "tfplan" ]; then
        terraform apply \
            -no-color \
            tfplan
    else
        echo -e "${RED}❌ No tfplan found. Run 'plan' action first.${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ Infrastructure deployed successfully${NC}"
}

# Output infrastructure details
show_outputs() {
    echo -e "\n${YELLOW}Infrastructure Outputs:${NC}"

    cd "$TERRAFORM_DIR"

    terraform output -json | jq . || true
}

# Destroy infrastructure (with confirmation)
destroy_terraform() {
    echo -e "\n${RED}⚠️  WARNING: This will destroy all infrastructure!${NC}"
    read -p "Type 'yes' to confirm: " confirm

    if [ "$confirm" != "yes" ]; then
        echo "Cancelled."
        exit 0
    fi

    echo -e "\n${YELLOW}Destroying infrastructure...${NC}"

    cd "$TERRAFORM_DIR"

    terraform destroy \
        -no-color

    echo -e "${GREEN}✅ Infrastructure destroyed${NC}"
}

# Post-deployment setup
post_deployment() {
    echo -e "\n${YELLOW}Running post-deployment setup...${NC}"

    # Create SNS subscription
    echo -e "\n${YELLOW}Create SNS subscription for alerts?${NC}"
    read -p "Enter email for alerts (or press Enter to skip): " alert_email

    if [ -n "$alert_email" ]; then
        SNS_TOPIC_ARN=$(cd "$TERRAFORM_DIR" && terraform output -raw sns_topic_arn)

        aws sns subscribe \
            --topic-arn "$SNS_TOPIC_ARN" \
            --protocol email \
            --notification-endpoint "$alert_email"

        echo -e "${GREEN}✅ Email subscription created (check your email to confirm)${NC}"
    fi

    # Store credentials
    echo -e "\n${YELLOW}Storing AWS credentials in Secrets Manager...${NC}"

    aws secretsmanager create-secret \
        --name capsa/jira/api-token \
        --description "Jira API token for CAPSA" \
        --secret-string "{\"url\":\"$(grep 'jira_url' $TERRAFORM_DIR/terraform.tfvars | cut -d'=' -f2 | tr -d ' \"')\",\"token\":\"$(grep 'jira_api_token' $TERRAFORM_DIR/terraform.tfvars | cut -d'=' -f2 | tr -d ' \"')\"}" \
        2>/dev/null || echo -e "${YELLOW}⚠️  Secret already exists${NC}"

    echo -e "${GREEN}✅ Credentials stored in Secrets Manager${NC}"
}

# Generate summary report
generate_summary() {
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Deployment Summary${NC}"
    echo -e "${GREEN}========================================${NC}"

    cd "$TERRAFORM_DIR"

    echo -e "\n${YELLOW}AWS Resources Created:${NC}"
    echo "  Staging Bucket: $(terraform output -raw staging_bucket_name 2>/dev/null || echo 'N/A')"
    echo "  Clean Bucket:   $(terraform output -raw clean_bucket_name 2>/dev/null || echo 'N/A')"
    echo "  Quarantine:     $(terraform output -raw quarantine_bucket_name 2>/dev/null || echo 'N/A')"
    echo "  SNS Topic:      $(terraform output -raw sns_topic_arn 2>/dev/null || echo 'N/A')"

    echo -e "\n${YELLOW}Next Steps:${NC}"
    echo "  1. Generate and upload test data:"
    echo "     python scripts/generate_test_data.py --size 1tb"
    echo ""
    echo "  2. Monitor scanning:"
    echo "     python scripts/monitor_scan.py"
    echo ""
    echo "  3. View scan results:"
    echo "     curl http://localhost:8000/results"
    echo ""
    echo "  4. Check quarantine bucket:"
    echo "     aws s3 ls capsa-quarantine-$(aws sts get-caller-identity --query Account --output text)/"
}

# Main execution
main() {
    case "$ACTION" in
        plan)
            check_prerequisites
            validate_config
            init_terraform
            validate_terraform
            plan_terraform
            ;;
        apply)
            check_prerequisites
            validate_config
            init_terraform
            apply_terraform
            show_outputs
            post_deployment
            generate_summary
            ;;
        destroy)
            check_prerequisites
            destroy_terraform
            ;;
        output)
            cd "$TERRAFORM_DIR"
            show_outputs
            ;;
        validate)
            check_prerequisites
            validate_config
            init_terraform
            validate_terraform
            ;;
        *)
            echo "Usage: $0 <environment> <action>"
            echo ""
            echo "Actions:"
            echo "  plan     - Plan infrastructure changes (default)"
            echo "  apply    - Apply infrastructure changes"
            echo "  destroy  - Destroy infrastructure"
            echo "  output   - Show infrastructure outputs"
            echo "  validate - Validate Terraform configuration"
            echo ""
            echo "Example:"
            echo "  $0 prod plan"
            echo "  $0 prod apply"
            exit 1
            ;;
    esac
}

main
