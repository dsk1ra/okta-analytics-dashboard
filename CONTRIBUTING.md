# Contributing

Thank you for your interest in contributing to Okta Analytics Dashboard.

## Prerequisites

- Python 3.12+
- Git

## Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/okta-analytics-dashboard.git
   cd okta-analytics-dashboard
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install --upgrade "pip<25"
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. Configure environment:
   ```bash
   cp .env.example .env
   ```

5. Run migrations:
   ```bash
   python manage.py migrate
   ```

## Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes.

3. Run quality checks:
   ```bash
   black .
   isort .
   ruff check .
   mypy .
   pytest
   ```

4. Commit with conventional messages:
   ```bash
   git commit -m "feat: description"
   git commit -m "fix: description"
   git commit -m "docs: description"
   ```

5. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. Create a pull request with a clear description of your changes.

## Commit Message Format

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `refactor:` - Code refactoring
- `test:` - Tests
- `chore:` - Maintenance

## Tests

All contributions should include tests:

```bash
pytest
pytest --cov=apps
```

## License

By contributing, you agree your contributions are licensed under the MIT License.
