.PHONY: fmt lint test up down clean init migrate db-up db-down ingest-run orchestrator-run worker-run up-all build-images build-all-images run-cli release-tag

# Default target
all: fmt lint test

# Format code
fmt:
	ruff format .
	ruff check --fix .

# Run linters
lint:
	ruff check .
	mypy scarabeo/ services/ analyzers/

# Run tests
test:
	pytest tests/ -v --tb=short -m "not slow"

# Run all tests including slow integration tests
test-all:
	pytest tests/ -v --tb=short

# Run only unit tests
test-unit:
	pytest tests/ -v --tb=short -m "unit"

# Run only integration tests
test-integration:
	pytest tests/ -v --tb=short -m "integration"

# Start infrastructure only (postgres, redis, minio)
up:
	docker-compose -f infra/docker-compose.yml up -d postgres redis minio minio-init

# Stop infrastructure
down:
	docker-compose -f infra/docker-compose.yml down

# Start all services (infra + orchestrator + worker + ingest)
up-all:
	docker-compose -f infra/docker-compose.yml up -d

# Stop all services
down-all:
	docker-compose -f infra/docker-compose.yml down

# Clean build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage

# Initialize development environment
init:
	python -m pip install --upgrade pip
	pip install -e ".[dev,ingest]"
	pre-commit install

# Run tests with coverage
coverage:
	pytest tests/ -v --tb=short --cov=scarabeo --cov=services --cov=analyzers --cov-report=html --cov-report=term-missing

# Type check only
typecheck:
	mypy scarabeo/ services/ analyzers/ --strict

# Security lint
security:
	bandit -r scarabeo/ services/ analyzers/ -ll

# Database migrations
migrate:
	alembic -c services/ingest/alembic.ini upgrade head

# Create new migration
db-migrate:
	alembic -c services/ingest/alembic.ini revision --autogenerate -m "$(MSG)"

# Rollback last migration
db-down:
	alembic -c services/ingest/alembic.ini downgrade -1

# Rollback all migrations
db-reset:
	alembic -c services/ingest/alembic.ini downgrade base

# Run ingest service
ingest-run:
	python -m services.ingest

# Run ingest service with reload (development)
ingest-dev:
	uvicorn services.ingest.app:app --reload --host 0.0.0.0 --port 8000

# Run orchestrator service
orchestrator-run:
	python -m services.orchestrator

# Run orchestrator service with reload (development)
orchestrator-dev:
	uvicorn services.orchestrator.app:app --reload --host 0.0.0.0 --port 8001

# Run worker service
worker-run:
	python -m services.worker

# Run retention service
retention-run:
	python -m services.worker.retention

# Run retention service (dry run)
retention-dry-run:
	python -m services.worker.retention --dry-run

# Build all Docker images
build-images:
	docker-compose -f infra/docker-compose.yml build

# Build triage analyzer image
build-analyzer:
	docker build -t scarabeo/triage-universal:latest -f analyzers/triage-universal/Dockerfile analyzers/triage-universal/

# Build all analyzer images
build-analyzers:
	docker build -t scarabeo/triage-universal:latest -f analyzers/triage-universal/Dockerfile analyzers/triage-universal/
	docker build -t scarabeo/pe-analyzer:latest -f analyzers/pe-analyzer/Dockerfile analyzers/pe-analyzer/
	docker build -t scarabeo/elf-analyzer:latest -f analyzers/elf-analyzer/Dockerfile analyzers/elf-analyzer/
	docker build -t scarabeo/script-analyzer:latest -f analyzers/script-analyzer/Dockerfile analyzers/script-analyzer/
	docker build -t scarabeo/doc-analyzer:latest -f analyzers/doc-analyzer/Dockerfile analyzers/doc-analyzer/
	docker build -t scarabeo/archive-analyzer:latest -f analyzers/archive-analyzer/Dockerfile analyzers/archive-analyzer/
	docker build -t scarabeo/similarity-analyzer:latest -f analyzers/similarity-analyzer/Dockerfile analyzers/similarity-analyzer/
	docker build -t scarabeo/yara-analyzer:latest -f analyzers/yara-analyzer/Dockerfile analyzers/yara-analyzer/
	docker build -t scarabeo/capa-analyzer:latest -f analyzers/capa-analyzer/Dockerfile analyzers/capa-analyzer/

# Create triage pipeline directory if missing
pipelines:
	mkdir -p pipelines
	touch pipelines/.gitkeep

# Initialize S3 bucket (dev)
init-s3:
	docker-compose -f infra/docker-compose.yml up minio-init

# View service logs
logs:
	docker-compose -f infra/docker-compose.yml logs -f

# View specific service logs
logs-service:
	docker-compose -f infra/docker-compose.yml logs -f $(SERVICE)

# Build all Docker images (services + analyzers)
build-all-images: build-images build-analyzers
	docker build -t scarabeo/cli:latest -f services/cli/Dockerfile .
	docker build -t scarabeo/api:latest -f services/api/Dockerfile .
	docker build -t scarabeo/search:latest -f services/search/Dockerfile .
	docker build -t scarabeo/web:latest -f services/web/Dockerfile .
	@echo "All images built successfully"

# Run CLI console
run-cli:
	python -m services.cli

# Run web console
run-web:
	python -m services.web

# Create release tag
release-tag:
	@echo "Creating release tag for version $(VERSION)"
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make release-tag VERSION=1.0.0"; \
		exit 1; \
	fi
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"
	@echo "Release tag v$(VERSION) created and pushed"

# Verify release readiness
release-check:
	@echo "Checking release readiness..."
	@python -c "from scarabeo.version import get_version; print(f'Version: {get_version()}')"
	@echo "Running tests..."
	$(MAKE) test
	@echo "Running linters..."
	$(MAKE) lint
	@echo "Release checks passed"
