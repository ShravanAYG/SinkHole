# AWS Auto-Deploy CI/CD (GitHub Actions)

This setup makes every push to `main` or `botwall` automatically deploy to your AWS server.

## What was added

- Workflow: `.github/workflows/deploy-aws.yml`
- Remote deploy script: `scripts/deploy_on_aws.sh`
- Service template: `deploy/systemd/botwall.service`

## 1. Prepare AWS server once

Run these on the server:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip
```

Create deployment folder and clone repo (if not already cloned):

```bash
mkdir -p /home/ubuntu/sinkhole
cd /home/ubuntu/sinkhole
git clone <repo_url> .
python3 -m venv .venv
.venv/bin/pip install -e .
```

Make deploy script executable:

```bash
chmod +x /home/ubuntu/sinkhole/scripts/deploy_on_aws.sh
```

## 2. Configure systemd service once

Copy and edit service file:

```bash
sudo cp /home/ubuntu/sinkhole/deploy/systemd/botwall.service /etc/systemd/system/botwall.service
sudo sed -i 's|^User=.*|User=ubuntu|' /etc/systemd/system/botwall.service
sudo sed -i 's|^WorkingDirectory=.*|WorkingDirectory=/home/ubuntu/sinkhole|' /etc/systemd/system/botwall.service
sudo sed -i 's|^ExecStart=.*|ExecStart=/home/ubuntu/sinkhole/.venv/bin/python -m botwall|' /etc/systemd/system/botwall.service
```

Set real secrets in the service file (required):

- `BOTWALL_SECRET_KEY`
- `BOTWALL_TELEMETRY_SECRET`

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable botwall
sudo systemctl restart botwall
sudo systemctl status botwall --no-pager
```

## 3. Add GitHub repository secrets

In GitHub repo settings, add these secrets:

- `AWS_HOST` = public DNS/IP of your server
- `AWS_USER` = SSH user (example: `ubuntu`)
- `AWS_SSH_PRIVATE_KEY` = private key content used to SSH into server
- `AWS_SSH_PORT` = `22` (or custom)
- `AWS_DEPLOY_DIR` = `/home/ubuntu/sinkhole`
- `AWS_REPO_URL` = git URL of this repository
- `AWS_SERVICE_NAME` = `botwall`
- `AWS_RUN_MIGRATIONS` = `0`
- `AWS_RUN_VALIDATE_LIVE` = `0` (set `1` only if your live env is always reachable)

## 4. How deploy works per push

On push to `main` or `botwall`:

1. GitHub runs tests
2. SSH into AWS server
3. Pulls latest branch in `/home/ubuntu/sinkhole`
4. Installs/updates Python deps in `.venv`
5. Runs smoke tests
6. Restarts `botwall` service

## 5. Verify end-to-end

Push a small commit, then check:

```bash
sudo journalctl -u botwall -n 80 --no-pager
sudo systemctl status botwall --no-pager
```

In GitHub Actions, confirm both jobs succeeded:

- `Run Tests`
- `Deploy on AWS Host`

## Notes

- If your repo is private and your server cannot pull without auth, use SSH deploy key or HTTPS token in `AWS_REPO_URL`.
- If you run botwall under a different service name, set `AWS_SERVICE_NAME` accordingly.
