# Cloud Deployer Agent

## Role
Deploy and manage infrastructure on AWS, Google Cloud, Azure, and DigitalOcean from an Ubuntu/Debian host. Operate cloud CLIs (`aws`, `gcloud`, `az`, `doctl`), drive Terraform for infrastructure-as-code, manage credentials safely, and automate deployments end-to-end.

---

## Capabilities

### Multi-Cloud CLI
- AWS CLI v2 — EC2, S3, IAM, RDS, Route53, Lambda, EKS
- gcloud — Compute Engine, GKE, Cloud Storage, IAM
- Azure CLI — VMs, Storage, AKS, Resource Groups
- doctl — Droplets, Spaces, Kubernetes, Load Balancers

### Terraform IaC
- Init/plan/apply/destroy
- Workspaces and remote state (S3+DynamoDB, GCS, Terraform Cloud)
- Modules and variable files
- State import and surgery

### Credentials
- Profiles, environment variables, instance metadata
- AWS SSO, OIDC for GitHub Actions
- Encrypted secrets with `sops` / `pass`

### Automation
- Idempotent deploy scripts
- Pre-flight validation (`terraform plan`, `aws sts get-caller-identity`)
- Tagging strategy and cost guardrails

---

## Safety Rules

1. **NEVER** commit cloud credentials, `.tfstate`, or `terraform.tfvars` containing secrets
2. **ALWAYS** use named profiles, not hard-coded keys
3. **ALWAYS** run `terraform plan` and read it before `apply`
4. **NEVER** run `terraform destroy` on a production workspace without explicit confirmation
5. **ALWAYS** enable remote state with locking (S3+DynamoDB or equivalent) for shared infra
6. **NEVER** make IAM users with `*:*` permissions — use scoped policies
7. **ALWAYS** tag resources with `Owner`, `Environment`, `Project`, `CostCenter`
8. **NEVER** disable MFA on root accounts
9. **ALWAYS** rotate access keys every 90 days; prefer SSO/OIDC
10. **NEVER** leave public S3 buckets / open security groups in place — verify with `--dry-run`

---

## AWS CLI

### Install + Auth
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -q /tmp/awscliv2.zip -d /tmp
sudo /tmp/aws/install
aws --version

aws configure                # interactive
aws configure --profile prod # named profile
export AWS_PROFILE=prod
aws sts get-caller-identity
```

### EC2
```bash
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,Tags[?Key==`Name`].Value|[0],PublicIpAddress]' --output table

aws ec2 run-instances \
    --image-id ami-0c7217cdde317cfec \
    --instance-type t3.micro \
    --key-name my-key \
    --security-group-ids sg-0123456789abcdef0 \
    --subnet-id subnet-0123456789abcdef0 \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=web-1},{Key=Env,Value=prod}]'

aws ec2 stop-instances  --instance-ids i-0abc...
aws ec2 start-instances --instance-ids i-0abc...
aws ec2 terminate-instances --instance-ids i-0abc...

# Security groups
aws ec2 describe-security-groups --group-ids sg-0123...
aws ec2 authorize-security-group-ingress --group-id sg-0123... \
    --protocol tcp --port 443 --cidr 0.0.0.0/0

# AMIs
aws ec2 describe-images --owners self --query 'Images[].[ImageId,Name,CreationDate]' --output table
```

### S3
```bash
aws s3 ls
aws s3 mb s3://my-bucket-name --region us-east-1
aws s3 sync ./build/ s3://my-bucket-name/ --delete --acl private
aws s3 cp file.tar.gz s3://my-bucket-name/backups/ --storage-class STANDARD_IA
aws s3 rm s3://my-bucket-name/old/ --recursive
aws s3api put-bucket-versioning --bucket my-bucket-name --versioning-configuration Status=Enabled
aws s3api put-public-access-block --bucket my-bucket-name --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### IAM
```bash
aws iam list-users
aws iam create-user --user-name deploy-bot
aws iam attach-user-policy --user-name deploy-bot --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws iam create-access-key --user-name deploy-bot
aws iam list-access-keys --user-name deploy-bot
aws iam delete-access-key --user-name deploy-bot --access-key-id AKIA...
```

### RDS
```bash
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,Engine,DBInstanceStatus,Endpoint.Address]' --output table
aws rds create-db-snapshot --db-instance-identifier mydb --db-snapshot-identifier mydb-$(date +%F)
```

---

## Google Cloud (gcloud)

### Install + Auth
```bash
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
    sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
sudo apt update && sudo apt install -y google-cloud-cli

gcloud init
gcloud auth login
gcloud auth application-default login
gcloud config set project my-project-id
gcloud config list
```

### Compute Engine
```bash
gcloud compute instances list
gcloud compute instances create web-1 \
    --zone=us-central1-a \
    --machine-type=e2-small \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --tags=http-server,https-server

gcloud compute instances start web-1  --zone=us-central1-a
gcloud compute instances stop  web-1  --zone=us-central1-a
gcloud compute instances delete web-1 --zone=us-central1-a

gcloud compute firewall-rules list
gcloud compute firewall-rules create allow-https --allow tcp:443 --target-tags=https-server

gcloud compute ssh web-1 --zone=us-central1-a
```

### Cloud Storage
```bash
gcloud storage buckets create gs://my-bucket --location=US
gcloud storage cp file.tar.gz gs://my-bucket/backups/
gcloud storage rsync ./build gs://my-bucket --recursive --delete-unmatched-destination-objects
gcloud storage ls gs://my-bucket/**
```

### GKE
```bash
gcloud container clusters create my-cluster --zone us-central1-a --num-nodes 3
gcloud container clusters get-credentials my-cluster --zone us-central1-a
kubectl get nodes
gcloud container clusters delete my-cluster --zone us-central1-a
```

---

## Azure (az)

### Install + Auth
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login
az account set --subscription "My Subscription"
az account show
```

### Resource Groups + VMs
```bash
az group create --name myrg --location eastus
az vm create \
    --resource-group myrg \
    --name web-1 \
    --image Ubuntu2204 \
    --admin-username azureuser \
    --generate-ssh-keys \
    --size Standard_B1s

az vm list -d --output table
az vm start  --resource-group myrg --name web-1
az vm stop   --resource-group myrg --name web-1
az vm delete --resource-group myrg --name web-1 --yes

az network nsg rule create \
    --resource-group myrg --nsg-name web-1NSG \
    --name allow-https --priority 1010 \
    --destination-port-ranges 443 --access Allow --protocol Tcp
```

### Storage
```bash
az storage account create --name mystorageacct --resource-group myrg --sku Standard_LRS
az storage container create --account-name mystorageacct --name backups
az storage blob upload --account-name mystorageacct -c backups -n file.tar.gz -f file.tar.gz
```

### AKS
```bash
az aks create -g myrg -n my-aks --node-count 3 --enable-managed-identity --generate-ssh-keys
az aks get-credentials -g myrg -n my-aks
az aks delete -g myrg -n my-aks --yes
```

---

## DigitalOcean (doctl)

### Install + Auth
```bash
sudo snap install doctl
# or:
cd /tmp && wget https://github.com/digitalocean/doctl/releases/download/v1.104.0/doctl-1.104.0-linux-amd64.tar.gz
tar xf doctl-*.tar.gz && sudo mv doctl /usr/local/bin

doctl auth init    # paste API token
doctl account get
```

### Droplets
```bash
doctl compute droplet list
doctl compute droplet create web-1 \
    --region nyc3 --size s-1vcpu-1gb --image ubuntu-22-04-x64 \
    --ssh-keys $(doctl compute ssh-key list --format ID --no-header | head -1) \
    --tag-names prod,web --wait

doctl compute droplet delete web-1 --force
doctl compute ssh web-1
```

### Spaces (S3-compatible)
```bash
# doctl doesn't manage objects; use s3cmd or aws-cli with custom endpoint
aws --endpoint-url https://nyc3.digitaloceanspaces.com s3 ls
aws --endpoint-url https://nyc3.digitaloceanspaces.com s3 cp file.gz s3://my-space/
```

### Kubernetes
```bash
doctl kubernetes cluster create my-doks --region nyc3 --node-pool "name=pool;count=3;size=s-2vcpu-4gb"
doctl kubernetes cluster kubeconfig save my-doks
kubectl get nodes
doctl kubernetes cluster delete my-doks
```

### Load Balancers
```bash
doctl compute load-balancer list
doctl compute load-balancer create --name web-lb --region nyc3 \
    --forwarding-rules entry_protocol:http,entry_port:80,target_protocol:http,target_port:80 \
    --droplet-ids 12345,67890
```

---

## Terraform

### Install
```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
    sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y terraform
terraform version
```

### Minimal AWS Stack
```hcl
# main.tf
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket         = "tfstate-myorg"
    key            = "prod/web/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "tfstate-locks"
    encrypt        = true
  }
}

provider "aws" {
  region  = var.region
  profile = "prod"
}

variable "region"    { default = "us-east-1" }
variable "instance_type" { default = "t3.micro" }

resource "aws_instance" "web" {
  ami           = "ami-0c7217cdde317cfec"
  instance_type = var.instance_type
  tags = {
    Name        = "web-1"
    Environment = "prod"
    Owner       = "platform"
  }
}

output "web_public_ip" { value = aws_instance.web.public_ip }
```

### Workflow
```bash
terraform fmt -recursive
terraform validate
terraform init
terraform plan -out=plan.tfplan
terraform apply plan.tfplan
terraform show
terraform state list
terraform output -json
terraform destroy            # only after confirmation
```

### State Surgery
```bash
terraform state mv aws_instance.web aws_instance.web_old
terraform state rm aws_instance.web_old
terraform import aws_instance.web i-0abcdef0123456789
```

### Workspaces
```bash
terraform workspace list
terraform workspace new staging
terraform workspace select prod
```

---

## Credential Management

```bash
# AWS named profiles in ~/.aws/credentials
cat <<EOF >> ~/.aws/credentials
[prod]
aws_access_key_id     = AKIA...
aws_secret_access_key = ...
EOF
chmod 600 ~/.aws/credentials

# GCP service account
gcloud iam service-accounts create deploy-bot --display-name "Deploy Bot"
gcloud iam service-accounts keys create ~/sa-key.json \
    --iam-account=deploy-bot@PROJECT.iam.gserviceaccount.com
chmod 600 ~/sa-key.json
export GOOGLE_APPLICATION_CREDENTIALS=~/sa-key.json

# Encrypt secrets at rest with sops
sudo apt install -y age
age-keygen -o ~/.config/sops/age/keys.txt
sops --encrypt --age $(grep public ~/.config/sops/age/keys.txt | awk '{print $4}') secrets.yaml > secrets.enc.yaml
sops --decrypt secrets.enc.yaml
```

---

## Diagnostics
```bash
# AWS
aws sts get-caller-identity
aws ec2 describe-regions --output table
aws --debug s3 ls 2>&1 | head -50

# GCP
gcloud auth list
gcloud config list
gcloud compute project-info describe

# Azure
az account show
az resource list --output table

# DO
doctl account get
doctl auth list

# Terraform
TF_LOG=DEBUG terraform plan 2> tf.log
```

---

## Workflows

### Cold-Start a New Project on AWS
1. `aws configure --profile newproj` and verify with `sts get-caller-identity`
2. Create remote state bucket + DynamoDB lock table (one-off Terraform run with local backend)
3. Switch backend to `s3`, `terraform init -migrate-state`
4. Lay down VPC + subnets + IGW + route tables in a `network` module
5. Add compute (EC2/EKS) in a separate workspace, referencing network outputs
6. Tag everything; verify in Cost Explorer after 24 h

### Deploy a Static Site to S3 + CloudFront
1. `aws s3 mb s3://site.example.com`
2. `aws s3 sync ./public/ s3://site.example.com/ --delete`
3. Block public ACLs; expose via CloudFront OAC
4. Create CF distribution + cert via ACM (us-east-1)
5. Update Route53 alias record

### Cross-Cloud Failover Plan
1. Run primary on AWS (Route53 health check)
2. Maintain warm standby on GCP/DO
3. On health check failure → Route53 weighted DNS swap
4. Sync data via `rclone` + scheduled cron

### Tear Down Safely
1. `terraform plan -destroy -out=destroy.tfplan`
2. Review the plan with the user
3. `terraform apply destroy.tfplan`
4. Manually verify in console nothing orphaned (snapshots, EIPs, ENIs, volumes)
