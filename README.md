# Okta Analytics Dashboard

[![Django CI](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/django.yml/badge.svg)](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/django.yml)
[![Docker CI](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/docker.yml/badge.svg)](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/docker.yml)
[![Dependency Health](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/deps.yml/badge.svg)](https://github.com/dsk1ra/okta-analytics-dashboard/actions/workflows/deps.yml)

**Okta Analytics Dashboard** is a Django-based analytics platform for ingesting, storing, and analysing Okta authentication and system log data. It is intended for security engineers, analysts, and operations teams who require visibility into Okta activity for monitoring and investigative purposes.

**Project status:** Alpha (pre-release). This project is under active development and is not yet intended for production use.

---

## Features

* Ingestion of Okta System Log data via the Okta API
* Persistent storage using MongoDB
* Redis-backed caching for improved performance
* Docker-based local development and deployment
* Extensible Django application architecture
* Foundational dashboard views for analytics visualisation

---

## Requirements

* Python 3.12 or later
* Django 5.2
* MongoDB 4.4 or later
* Redis 6.0 or later
* Docker and Docker Compose (optional, recommended)

---

## Quick Start

### Local Development

1. Clone the repository:

   ```bash
   git clone https://github.com/dsk1ra/okta-analytics-dashboard.git
   cd okta-analytics-dashboard
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
   ```

3. Install dependencies:

   ```bash
   pip install --upgrade "pip<25"
   pip install -r requirements.txt
   ```

4. Configure environment variables:

   ```bash
   cp .env.example .env
   # Update .env with your Okta credentials and service configuration
   ```

5. Apply database migrations:

   ```bash
   python manage.py migrate
   ```

6. Start the development server:

   ```bash
   python manage.py runserver
   ```

The application will be available at [http://localhost:8000](http://localhost:8000)

---

### Docker Deployment

For local development or evaluation using Docker:

```bash
docker compose up --build
```

---

## Configuration

The following environment variables are required. Values should be provided via a `.env` file or a secure secrets management mechanism.

```env
# Django
DJANGO_SECRET_KEY=<your-secret-key>
DEBUG=False
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1

# MongoDB
MONGO_HOST=mongodb
MONGO_PORT=27017
MONGO_DB_NAME=okta_dashboard
MONGODB_URL=mongodb://<user>:<password>@<host>:<port>/<database>

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

### Security Notes

* Okta API tokens and client secrets must never be committed to source control
* Use environment variables or a dedicated secrets manager for sensitive configuration
* This project has not yet undergone a formal security review

---

## Development

### Running Tests

```bash
pytest
```

### Code Quality and Static Analysis

```bash
black .
isort .
ruff check .
mypy .
```

### Development Dependencies

```bash
pip install -r requirements-dev.txt
```

---

## Common Management Commands

```bash
# Fetch Okta logs
python manage.py fetch_okta_logs_dpop

# Create an administrative user
python manage.py createsuperuser

# Open Django shell
python manage.py shell

# Collect static files (production)
python manage.py collectstatic --noinput
```

---

## Versioning and Releases

This project follows Semantic Versioning (MAJOR.MINOR.PATCH) with pre-release identifiers during early development.

Current release: `v0.1.0-alpha.1`

Release notes and checklists are available in [RELEASE.md](RELEASE.md).

---

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and workflow expectations.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
