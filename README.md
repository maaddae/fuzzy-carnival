# SecretsHunter

A Django-based API for scanning GitHub repositories to detect potential secrets and sensitive information in code.

[![Built with Cookiecutter Django](https://img.shields.io/badge/built%20with-Cookiecutter%20Django-ff69b4.svg?logo=cookiecutter)](https://github.com/cookiecutter/cookiecutter-django/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

License: MIT

## Description

SecretsHunter is a security scanning tool that analyzes public GitHub repositories for exposed secrets, API keys, passwords, and other sensitive information. It detects various types of secrets including AWS keys, GitHub tokens, private SSH/RSA keys, API keys (Stripe, Google, Slack), database connection strings, hardcoded passwords, JWT tokens, and OAuth tokens.

## Getting Started

### Prerequisites

- Docker and Docker Compose
- GitHub Personal Access Token

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/maaddae/fuzzy-carnival.git
   cd secretshunter
   ```

2. **Set up environment variables**

   Create a `.envs/.local/.django` file with your GitHub token:
   ```bash
   GITHUB_TOKEN=your_github_personal_access_token_here
   ```

3. **Start the application**
   ```bash
   docker compose -f docker-compose.local.yml up -d
   ```

4. **Create a superuser**
   ```bash
   docker compose -f docker-compose.local.yml exec django python manage.py createsuperuser
   ```

5. **Access the application**
   - API Documentation: `http://localhost:8000/api/docs/`
   - Admin Panel: `http://localhost:8000/admin/`
   - Mailpit: `http://localhost:8025/`

## Core Functionality

### API Endpoints

- `POST /api/scans/` - Scan a GitHub repository for secrets
- `POST /api/scans/idempotent/` - Smart scanning with commit SHA deduplication
- `GET /api/scans/` - List all scans
- `GET /api/scans/{id}/` - Retrieve detailed scan results
- `POST /api/scans/{id}/create-issue/` - Create a GitHub issue for scan findings
- `PATCH /api/scans/{id}/mark_false_positive/` - Mark findings as false positives

### Features

- Asynchronous scanning with Celery
- Idempotent scans using commit SHA tracking
- 13+ secret detection patterns
- Context preservation for findings
- File filtering (binaries, dependencies, build artifacts)
- GitHub API rate limit handling
- **Automatic GitHub issue creation** for findings (configurable)
- Manual issue creation via API endpoint
- False positive management
- Real-time scan status tracking

## Configuration

### Auto-Creating GitHub Issues

SecretsHunter can automatically create GitHub issues when secrets are found. Configure in `.envs/.local/.django`:

```bash
# Disable automatic issue creation after scan completion
AUTO_CREATE_GITHUB_ISSUES=False

# Minimum findings required to create an issue (default: 1)
AUTO_CREATE_ISSUE_THRESHOLD=1

# Delay in seconds before creating issue (default: 5)
AUTO_CREATE_ISSUE_DELAY=5
```

When enabled:
- Issues are created automatically after scan completion
- Only created if findings meet the threshold
- Respects repository permissions (issues must be enabled)
- Includes detailed Markdown report of all findings
- Labeled as "security" for easy filtering

You can also manually trigger issue creation via the API:
```bash
curl -X POST "http://localhost:8000/api/scans/{scan_id}/create-issue/" \
  -H "Authorization: Token your_api_token"
```
