# CampusVault Deployment Guide (Render)

This repository includes a Render Blueprint (`render.yaml`) configured for a single web instance and a persistent disk. SQLite and uploaded files are stored on that disk so they survive redeploys.

## Deploy
1. Create a GitHub repository and push this project folder (do not commit `.env`, database files, or uploaded files).
2. On Render, choose **New + > Blueprint** and connect the GitHub repository.
3. Review the service and persistent disk configuration. A paid persistent disk may be required by the platform; verify current pricing before proceeding.
4. Set `ADMIN_EMAIL` to the email address of an account you register after first deploy. If you have not registered it yet, deploy, register, then update the environment variable and redeploy.
5. Render generates `SECRET_KEY` through the blueprint. Keep it private and stable across deploys.
6. Wait for deployment and open the generated public URL. Register, log in, and verify upload/download, bookmarks, reports and admin functions.

## Persistence / scaling warning
This deployment intentionally uses SQLite on a persistent disk and one service instance. Do not scale horizontally or run multiple app instances against this SQLite database. For larger/public usage, migrate to PostgreSQL, move uploads to object storage, use distributed rate limiting, add malware scanning, backups, monitoring, and a security review.

## Docker
Build: `docker build -t campusvault .`
Run with persistent storage: `docker run --rm -p 8000:8000 -e SECRET_KEY='a-long-secret' -e FLASK_ENV=production -e ADMIN_EMAIL='admin@example.com' -v campusvault-data:/data campusvault`

Visit `http://localhost:8000`.

Phase 5 adds PyMuPDF. Ensure the deployment build installs the updated requirements.txt. The local NLP feature needs no API keys.
