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

#### Scanning
- `POST /api/scans/` - Scan a GitHub repository for secrets
- `POST /api/scans/idempotent/` - Smart scanning with commit SHA deduplication
- `GET /api/scans/` - List all scans
- `GET /api/scans/{id}/` - Retrieve detailed scan results
- `POST /api/scans/{id}/create-issue/` - Create a GitHub issue for scan findings
- `PATCH /api/scans/{id}/mark_false_positive/` - Mark findings as false positives

#### Watchlist
- `POST /api/watchlist/` - Add repository to watchlist
- `GET /api/watchlist/` - List watched repositories
- `GET /api/watchlist/{id}/` - Get watchlist entry details
- `PATCH /api/watchlist/{id}/` - Update scan interval or active status
- `DELETE /api/watchlist/{id}/` - Remove repository from watchlist
- `POST /api/watchlist/{id}/scan_now/` - Trigger immediate scan

### Features

- Asynchronous scanning with Celery
- **Repository watchlist with periodic scanning** at configurable intervals
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

### Repository Watchlist

Add repositories to a watchlist for automatic periodic scanning:

```bash
# Add a repository to the watchlist
curl -X POST http://localhost:8000/api/watchlist/ \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/owner/repo",
    "scan_interval": 86400
  }'
```

**Available scan intervals:**
- `3600` - Every Hour
- `21600` - Every 6 Hours
- `86400` - Daily (default)
- `604800` - Weekly

**Watchlist features:**
- Automatic periodic scanning at configured intervals
- Track scan history and statistics
- Enable/disable monitoring without removing entries
- Manual scan trigger via API
- Next scan scheduling

**Trigger immediate scan:**
```bash
curl -X POST http://localhost:8000/api/watchlist/{id}/scan_now/
```

**List watched repositories:**
```bash
curl http://localhost:8000/api/watchlist/
```

**Update scan interval:**
```bash
curl -X PATCH http://localhost:8000/api/watchlist/{id}/ \
  -H "Content-Type: application/json" \
  -d '{"scan_interval": 3600, "is_active": true}'
```

curl -X POST "http://localhost:8000/api/scans/{scan_id}/create-issue/" \
  -H "Authorization: Token your_api_token"
```

## Assumptions, Limitations, and Trade-offs

### **Assumptions**

1. **Public Repositories Only**
   - The scanner only works with public GitHub repositories
   - Private repository support would require OAuth flow and repository permissions

2. **GitHub API Rate Limits**
   - Assumes a valid GitHub Personal Access Token is provided
   - Unauthenticated requests: 60 requests/hour
   - Authenticated requests: 5,000 requests/hour
   - Large repositories may consume significant rate limit quota

3. **Repository Size**
   - Assumes repositories are reasonably sized
   - Very large repositories may timeout or consume excessive resources
   - Default timeout: 10 minutes per scan

4. **Pattern Matching Accuracy**
   - Regex patterns are designed to minimize false positives
   - Minimum length requirements (e.g., 20 chars for API keys)
   - May miss some secrets with unusual formats or encodings

5. **Network Connectivity**
   - Assumes reliable network connection to GitHub API
   - No offline scanning capability

### **Limitations**

1. **Secret Detection**
   - **Pattern-based only**: Uses regex patterns, not entropy analysis or ML
   - **No context awareness**: Cannot distinguish between real secrets and test data
   - **Base64 encoded secrets**: Not automatically detected
   - **Obfuscated secrets**: String concatenation or encoded values may be missed
   - **Language-specific formats**: May not catch all language-specific secret patterns

2. **Performance**
   - **Synchronous file fetching**: Files are scanned sequentially from GitHub API
   - **No caching**: Each scan fetches fresh data (idempotent scans use commit SHA)
   - **Memory usage**: Large files loaded entirely into memory
   - **Binary file detection**: Basic heuristics, not foolproof

3. **Scalability**
   - **Single-threaded scanning**: One repository scanned at a time per worker
   - **No distributed scanning**: Cannot split large repo across multiple workers
   - **Database bottleneck**: All findings stored in PostgreSQL (not optimized for massive scale)

4. **GitHub Issue Creation**
   - **Requires repository issues enabled**: Cannot create issues if disabled by owner
   - **No update mechanism**: Cannot update existing issues with new findings
   - **Rate limit aware**: But doesn't implement exponential backoff for 403 errors
   - **No duplicate detection**: May create multiple issues for same repository

5. **Watchlist**
   - **No webhook support**: Relies on periodic polling instead of GitHub webhooks
   - **Fixed intervals**: Cannot trigger scans based on push events
   - **No priority queue**: All repositories treated equally regardless of risk

6. **Security**
   - **API authentication**: Currently allows anonymous scans (AllowAny permission)
   - **No rate limiting**: Application-level rate limiting not implemented

### **Trade-offs**

1. **Pattern Matching vs ML**
   - **Chosen**: Regex-based pattern matching
   - **Trade-off**: Faster, deterministic, but less accurate than ML models
   - **Rationale**: Simpler to implement, maintain, and explain; no training data required

2. **Synchronous vs Async Scanning**
   - **Chosen**: Celery tasks for async scanning
   - **Trade-off**: More complex infrastructure (Redis, workers) but better UX
   - **Rationale**: Allows API to return immediately; handles long-running scans gracefully

3. **GitHub API vs Git Clone**
   - **Chosen**: GitHub REST API
   - **Trade-off**: Rate limited but no disk space requirements
   - **Rationale**: Simpler, no local git operations, works in containers

4. **PostgreSQL vs NoSQL**
   - **Chosen**: PostgreSQL for all data
   - **Trade-off**: Strong consistency but potential performance bottleneck at scale
   - **Rationale**: Django ORM support, ACID guarantees, relational data model fits use case

5. **False Positive Handling**
   - **Chosen**: Manual marking by users
   - **Trade-off**: Requires human review but allows learning
   - **Rationale**: No ML model to train; simple implementation

6. **Issue Auto-creation**
   - **Chosen**: Optional auto-creation with configurable threshold
   - **Trade-off**: May create noise but ensures visibility
   - **Rationale**: Configurable gives users control; defaults to off

## Future Improvements

### **With More Time (Priority Order)**

#### **High Priority**

1. **Enhanced Secret Detection**
   - Implement entropy analysis for detecting high-randomness strings
   - Add machine learning model for context-aware detection
   - Support for base64/hex encoded secrets
   - Custom regex pattern upload by users
   - Confidence scoring for findings

2. **Performance Optimization**
   - Implement concurrent file fetching using `asyncio` or `httpx`
   - Add Redis caching for repository metadata and file contents
   - Stream large files instead of loading into memory
   - Batch database inserts for findings
   - Add database indexes for common queries

3. **Webhook Support**
   - GitHub webhook integration for real-time scanning
   - Scan on push events instead of periodic polling
   - Priority queue for recently updated repositories

4. **Authentication & Authorization**
   - JWT token-based API authentication
   - User registration and login
   - Organization/team support with role-based access
   - OAuth integration with GitHub
   - API rate limiting per user/organization

5. **Improved GitHub Integration**
   - Support for private repositories via OAuth
   - Update existing issues with new findings
   - Close issues when secrets are remediated
   - GitHub App instead of personal access tokens
   - Repository suggestions based on user's GitHub access

#### **Medium Priority**

6. **Advanced Reporting**
   - Trend analysis dashboard (findings over time)
   - Export findings to CSV/JSON/PDF
   - Integration with security tools (SIEM, Slack, PagerDuty)
   - Risk scoring based on secret type and exposure time
   - Compliance reports (SOC 2, ISO 27001)

7. **False Positive Reduction**
   - Machine learning model trained on labeled data
   - Common test patterns whitelist
   - Repository-specific ignore patterns (`.secretshunterignore`)
   - Feedback loop for improving patterns

8. **Scalability**
   - Horizontal scaling of Celery workers
   - Task distribution across multiple queues
   - Implement job prioritization
   - Add monitoring and alerting (Prometheus, Grafana)
   - Database read replicas for reporting queries

9. **Multi-Platform Support**
   - GitLab repository scanning
   - Bitbucket support
   - Local git repository scanning
   - S3 bucket scanning
   - Docker image scanning

#### **Low Priority**

10. **Developer Experience**
    - CLI tool for local scanning
    - VS Code extension
    - Pre-commit hooks integration
    - Real-time scanning during code review
    - IDE plugins (IntelliJ, PyCharm)

11. **Advanced Features**
    - Secret rotation workflow integration
    - Automated remediation suggestions
    - Integration with secret management tools (Vault, AWS Secrets Manager)
    - Historical secret tracking across commits
    - Diff-based scanning (only changed files)

12. **Testing & Quality**
    - Integration tests for GitHub API mocking
    - Load testing with large repositories
    - Chaos engineering for failure scenarios
    - Performance benchmarking suite
    - A/B testing for detection algorithms
