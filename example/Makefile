.PHONY: help setup install migrate superuser run clean test check shell collectstatic postman postman-install

help:
	@echo "========================================="
	@echo "Axioms DRF Example - Makefile Commands"
	@echo "========================================="
	@echo ""
	@echo "Setup Commands:"
	@echo "  make setup        - Complete setup (env, install, migrate)"
	@echo "  make install      - Install Python dependencies"
	@echo "  make migrate      - Run database migrations"
	@echo "  make superuser    - Create Django superuser"
	@echo ""
	@echo "Development Commands:"
	@echo "  make run          - Start development server"
	@echo "  make shell        - Open Django shell"
	@echo "  make check        - Run Django system checks"
	@echo ""
	@echo "Testing Commands:"
	@echo "  make postman      - Run Postman collection tests via Newman CLI"
	@echo "  make postman-install - Install Newman (Postman CLI)"
	@echo ""
	@echo "Database Commands:"
	@echo "  make migrations   - Create new migrations"
	@echo "  make migrate      - Apply migrations"
	@echo "  make showmigrations - Show migration status"
	@echo ""
	@echo "Utility Commands:"
	@echo "  make clean        - Remove generated files"
	@echo "  make collectstatic - Collect static files"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. make setup"
	@echo "  2. Edit .env with your configuration"
	@echo "  3. make run"
	@echo ""

setup: env-check install migrate
	@echo ""
	@echo "========================================="
	@echo "Setup Complete!"
	@echo "========================================="
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit .env and configure AXIOMS_DOMAIN and AXIOMS_AUDIENCE"
	@echo "2. Run: make run"
	@echo "3. Import Axioms_DRF_Example.postman_collection.json into Postman"
	@echo ""
	@echo "The API will be available at: http://localhost:8000/api/"
	@echo ""

env-check:
	@if [ ! -f .env ]; then \
		echo "Creating .env file from .env.example..."; \
		cp .env.example .env; \
		echo "✓ .env file created"; \
		echo ""; \
		echo "⚠️  IMPORTANT: Edit .env and set your AXIOMS_DOMAIN and AXIOMS_AUDIENCE"; \
		echo ""; \
	else \
		echo "✓ .env file already exists"; \
		echo ""; \
	fi

install:
	@echo "Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "✓ Dependencies installed"
	@echo ""

migrate:
	@echo "Running database migrations..."
	python manage.py makemigrations
	python manage.py migrate
	@echo "✓ Migrations complete"
	@echo ""

migrations:
	@echo "Creating new migrations..."
	python manage.py makemigrations
	@echo "✓ Migrations created"

showmigrations:
	@echo "Migration status:"
	@python manage.py showmigrations

superuser:
	@echo "Creating Django superuser..."
	python manage.py createsuperuser
	@echo "✓ Superuser created"

run:
	@echo "Starting development server..."
	@echo "API available at: http://localhost:8000/api/"
	@echo "Admin available at: http://localhost:8000/admin/"
	@echo ""
	python manage.py runserver

shell:
	@echo "Opening Django shell..."
	python manage.py shell

check:
	@echo "Running Django system checks..."
	python manage.py check

clean:
	@echo "Cleaning up generated files..."
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	rm -f db.sqlite3
	rm -rf staticfiles/
	@echo "✓ Cleanup complete"

collectstatic:
	@echo "Collecting static files..."
	python manage.py collectstatic --noinput
	@echo "✓ Static files collected"

# Production-related commands
prod-check:
	@echo "Running production readiness checks..."
	@echo ""
	@echo "Checking environment variables..."
	@if grep -q "DJANGO_SECRET_KEY=your-secret-key" .env 2>/dev/null; then \
		echo "❌ WARNING: Using default SECRET_KEY"; \
	else \
		echo "✓ SECRET_KEY configured"; \
	fi
	@if grep -q "DEBUG=True" .env 2>/dev/null; then \
		echo "❌ WARNING: DEBUG is enabled"; \
	else \
		echo "✓ DEBUG is disabled"; \
	fi
	@echo ""
	@python manage.py check --deploy

# Docker commands (if needed in future)
docker-build:
	docker build -t axioms-drf-example .

docker-run:
	docker run -p 8000:8000 --env-file .env axioms-drf-example
