# SinkHole — AWS Docker Deployment Guide

Deploy SinkHole as a standalone Docker container on AWS to protect **any website**.

## Architecture

```
Internet → ALB (port 443) → ECS Fargate (SinkHole) → Your Website
```

SinkHole sits between your load balancer and your website. It inspects every request, blocks bots, and proxies clean traffic through to your origin.

---

## Step 1: Create an ECR Repository

```bash
aws ecr create-repository \
  --repository-name sinkhole \
  --region ap-south-1 \
  --image-scanning-configuration scanOnPush=true
```

Note the `repositoryUri` — you'll need it (e.g. `123456789.dkr.ecr.ap-south-1.amazonaws.com/sinkhole`).

## Step 2: Build & Push the Docker Image

```bash
# Login to ECR
aws ecr get-login-password --region ap-south-1 | \
  docker login --username AWS --password-stdin 123456789.dkr.ecr.ap-south-1.amazonaws.com

# Build the image
docker build -t sinkhole .

# Tag and push
docker tag sinkhole:latest 123456789.dkr.ecr.ap-south-1.amazonaws.com/sinkhole:latest
docker push 123456789.dkr.ecr.ap-south-1.amazonaws.com/sinkhole:latest
```

## Step 3: Create ECS Task Definition

Create `ecs-task-definition.json`:

```json
{
  "family": "sinkhole",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT_ID:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "sinkhole",
      "image": "ACCOUNT_ID.dkr.ecr.ap-south-1.amazonaws.com/sinkhole:latest",
      "portMappings": [
        { "containerPort": 80, "protocol": "tcp" }
      ],
      "environment": [
        { "name": "UPSTREAM_URL", "value": "http://your-website.internal:3000" },
        { "name": "BOTWALL_SECRET_KEY", "value": "YOUR-STRONG-SECRET-KEY" },
        { "name": "BOTWALL_TELEMETRY_SECRET", "value": "YOUR-TELEMETRY-KEY" }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -sf http://localhost:4000/healthz || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 15
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/sinkhole",
          "awslogs-region": "ap-south-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

Register it:
```bash
aws ecs register-task-definition --cli-input-json file://ecs-task-definition.json
```

## Step 4: Create ECS Service with ALB

```bash
# 1. Create ECS Cluster
aws ecs create-cluster --cluster-name sinkhole-cluster

# 2. Create Application Load Balancer (via Console or CLI)
# Target group should point to port 80, health check on /healthz

# 3. Create the ECS Service
aws ecs create-service \
  --cluster sinkhole-cluster \
  --service-name sinkhole-service \
  --task-definition sinkhole \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=sinkhole,containerPort=80"
```

## Step 5: DNS Setup

Point your domain's DNS to the ALB:

```
yourdomain.com → CNAME → sinkhole-alb-xxx.ap-south-1.elb.amazonaws.com
```

Or use Route 53 with an A-record alias.

---

## Using with Different Websites

### Scenario A: Protect a website on the same VPC

Set `UPSTREAM_URL` to the private DNS or IP:
```
UPSTREAM_URL=http://10.0.1.50:3000
UPSTREAM_URL=http://my-app.internal:8080
```

### Scenario B: Protect an external website

Set `UPSTREAM_URL` to the public URL:
```
UPSTREAM_URL=https://my-website.com
```

### Scenario C: Protect a website in another ECS service

Use the service discovery name:
```
UPSTREAM_URL=http://my-app.local:3000
```

---

## GitHub Actions CI/CD (Automated)

The repo includes `.github/workflows/deploy-aws.yml` that automatically:
1. Runs tests on push
2. Builds the Docker image
3. Pushes to ECR
4. Updates the ECS service

### Required GitHub Secrets

| Secret | Example |
|--------|---------|
| `AWS_ACCESS_KEY_ID` | `AKIAIOSFODNN7EXAMPLE` |
| `AWS_SECRET_ACCESS_KEY` | `wJalrXUtnFEMI/K7MDENG/...` |
| `AWS_REGION` | `ap-south-1` |
| `ECR_REPOSITORY` | `sinkhole` |
| `ECS_CLUSTER` | `sinkhole-cluster` |
| `ECS_SERVICE` | `sinkhole-service` |
| `ECS_TASK_DEFINITION` | `sinkhole` |

---

## Production Checklist

- [ ] Set strong `BOTWALL_SECRET_KEY` (use `openssl rand -hex 32`)
- [ ] Set strong `BOTWALL_TELEMETRY_SECRET`
- [ ] Enable HTTPS on ALB (ACM certificate)
- [ ] Set up CloudWatch log group `/ecs/sinkhole`
- [ ] Configure auto-scaling (target tracking on CPU/memory)
- [ ] Add `<script src="/bw/sdk.js" defer></script>` to your website's HTML
- [ ] For multi-instance: enable Redis (`BOTWALL_REDIS_ENABLED=1`)

## Scaling with Redis

For multi-container deployments (2+ tasks), enable Redis to share session state:

```json
{ "name": "BOTWALL_REDIS_ENABLED", "value": "1" },
{ "name": "BOTWALL_REDIS_URL", "value": "redis://your-elasticache.xxx.cache.amazonaws.com:6379/0" }
```

Use Amazon ElastiCache (Redis) in the same VPC.
