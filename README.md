# Okta Analytics Dashboard

[![Django CI](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/django.yml/badge.svg)](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/django.yml)
[![Docker CI](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/docker.yml/badge.svg)](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/docker.yml)
[![Dependency Health](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/deps.yml/badge.svg)](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/deps.yml)

Django-based analytics dashboard for Okta system logs. Integrates with Okta APIs to collect and display authentication logs, system events, and security metrics.

## Requirements

- Python 3.12+
- Django 5.2
- MongoDB 4.4+
- Redis 6.0+
- Docker & Docker Compose (optional)

## Quick Start

### Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/dsk1ra/okta-analytics-dashboard.git
   cd okta-analytics-dashboard
   ```

2. Create virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install --upgrade "pip<25"
   pip install -r requirements.txt
   ```

4. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env with your Okta credentials and database settings
   ```

5. Run migrations:
   ```bash
   python manage.py migrate
   ```

6. Start development server:
   ```bash
   python manage.py runserver
   ```

Access the application at http://localhost:8000

### Docker Deployment

```bash
docker compose up --build
```

## Configuration

Required environment variables in `.env`:

```
# Django
DJANGO_SECRET_KEY=<your-secret-key>
DEBUG=False
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1

# Database
MONGO_HOST=mongodb
MONGO_PORT=27017
MONGO_DB_NAME=okta_dashboard
MONGODB_URL=mongodb://<user>:<pass>@<host>:<port>/<dbname>

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
CACHE_TIMEOUT=300

# Okta
OKTA_ORG_URL=https://<your-org>.okta.com
OKTA_CLIENT_ID=<client-id>
OKTA_CLIENT_SECRET=<client-secret>
OKTA_API_TOKEN=<api-token>
```

## Development

### Run Tests

```bash
pytest
```

### Run Code Quality Checks

```bash
black .
isort .
ruff check .
mypy .
```

### Install Development Dependencies

```bash
pip install -r requirements-dev.txt
```

## Common Commands

```bash
# Fetch Okta logs
python manage.py fetch_okta_logs_dpop

# Create superuser
python manage.py createsuperuser

# Django shell
python manage.py shell

# Collect static files (production)
python manage.py collectstatic --noinput
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
