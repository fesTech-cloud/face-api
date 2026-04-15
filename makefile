# ─────────────────────────────────────────────────────────────────────────────
# Face API — Makefile
# ─────────────────────────────────────────────────────────────────────────────

APP_NAME   := face-api
CMD_PATH   := .
BIN_DIR    := ./bin
BIN        := $(BIN_DIR)/$(APP_NAME)
DOCKER_IMG := $(APP_NAME):latest
GO         := go
CGO_ENABLED := 1

# Load .env if it exists (for local make targets)
ifneq (,$(wildcard .env))
	include .env
	export
endif

.PHONY: help
help: ## Show this help message
	@echo ''
	@echo '  $(APP_NAME) — available commands'
	@echo ''
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ''

# ─────────────────────────────────────────────────────────────────────────────
# Development
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: run
run: ## Run the server locally (no Docker)
	@CGO_ENABLED=$(CGO_ENABLED) $(GO) run $(CMD_PATH)/...

.PHONY: dev
dev: ## Run with hot-reload using air
	@which air > /dev/null 2>&1 || (echo "Installing air..." && go install github.com/air-verse/air@latest)
	@air

.PHONY: build
build: ## Build the binary
	@mkdir -p $(BIN_DIR)
	@echo "Building $(APP_NAME)..."
	@CGO_ENABLED=$(CGO_ENABLED) $(GO) build -ldflags="-w -s" -o $(BIN) $(CMD_PATH)
	@echo "Binary ready: $(BIN)"

.PHONY: clean
clean: ## Remove build artifacts
	@rm -rf $(BIN_DIR)
	@echo "Cleaned."

# ─────────────────────────────────────────────────────────────────────────────
# Testing
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run all tests
	@CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./... -v -count=1

.PHONY: test-short
test-short: ## Run tests without integration tests
	@CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./... -short -count=1

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@mkdir -p coverage
	@CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./... -coverprofile=coverage/coverage.out
	@$(GO) tool cover -html=coverage/coverage.out -o coverage/coverage.html
	@echo "Coverage report: coverage/coverage.html"

.PHONY: bench
bench: ## Run benchmarks
	@CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./... -bench=. -benchmem

# ─────────────────────────────────────────────────────────────────────────────
# Code quality
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: lint
lint: ## Run golangci-lint
	@which golangci-lint > /dev/null 2>&1 || \
		(echo "Installing golangci-lint..." && \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin)
	@golangci-lint run ./...

.PHONY: fmt
fmt: ## Format all Go code
	@$(GO) fmt ./...
	@echo "Formatted."

.PHONY: vet
vet: ## Run go vet
	@CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	@$(GO) mod tidy

.PHONY: check
check: fmt vet lint ## Run fmt + vet + lint

# ─────────────────────────────────────────────────────────────────────────────
# Docker
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: docker-build
docker-build: ## Build the Docker image
	@echo "Building Docker image $(DOCKER_IMG)..."
	@docker build -t $(DOCKER_IMG) .

.PHONY: docker-run
docker-run: ## Run the API container only (no compose)
	@docker run --rm -p 8080:8080 \
		--env-file .env \
		-v $(PWD)/models:/app/models:ro \
		$(DOCKER_IMG)

.PHONY: docker-push
docker-push: docker-build ## Build and push image to registry
	@docker push $(DOCKER_IMG)

# ─────────────────────────────────────────────────────────────────────────────
# Docker Compose
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: up
up: ## Start all services (postgres, redis, api)
	@docker compose up -d
	@echo ""
	@echo "  API      → http://localhost:$(API_PORT)"
	@echo "  Postgres → localhost:$(POSTGRES_PORT)"
	@echo "  Redis    → localhost:$(REDIS_PORT)"
	@echo ""

.PHONY: up-dev
up-dev: ## Start all services including pgAdmin
	@docker compose --profile dev up -d
	@echo ""
	@echo "  API      → http://localhost:$(API_PORT)"
	@echo "  pgAdmin  → http://localhost:$(PGADMIN_PORT)"
	@echo ""

.PHONY: down
down: ## Stop all services
	@docker compose down

.PHONY: down-v
down-v: ## Stop all services and DELETE volumes (wipes data)
	@docker compose down -v
	@echo "All volumes removed."

.PHONY: restart
restart: down up ## Restart all services

.PHONY: restart-api
restart-api: ## Restart only the API container
	@docker compose restart api

.PHONY: rebuild
rebuild: ## Rebuild and restart the API container
	@docker compose up -d --build api

.PHONY: logs
logs: ## Tail logs from all services
	@docker compose logs -f

.PHONY: logs-api
logs-api: ## Tail logs from the API only
	@docker compose logs -f api

.PHONY: ps
ps: ## Show running containers
	@docker compose ps

# ─────────────────────────────────────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: db-shell
db-shell: ## Open a psql shell inside the postgres container
	@docker compose exec postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)

.PHONY: db-migrate
db-migrate: ## Run all pending SQL migrations
	@echo "Running migrations..."
	@for f in migrations/*.sql; do \
		echo "  applying $$f"; \
		docker compose exec -T postgres psql \
			-U $(POSTGRES_USER) -d $(POSTGRES_DB) < $$f; \
	done
	@echo "Migrations done."

.PHONY: db-reset
db-reset: ## Drop and recreate the database (DEV ONLY)
	@echo "WARNING: This will delete all data. Press Ctrl+C to cancel..."
	@sleep 3
	@docker compose exec postgres psql -U $(POSTGRES_USER) \
		-c "DROP DATABASE IF EXISTS $(POSTGRES_DB);"
	@docker compose exec postgres psql -U $(POSTGRES_USER) \
		-c "CREATE DATABASE $(POSTGRES_DB);"
	@$(MAKE) db-migrate
	@echo "Database reset complete."

.PHONY: redis-shell
redis-shell: ## Open a redis-cli shell
	@docker compose exec redis redis-cli -a $(REDIS_PASSWORD)

.PHONY: redis-flush
redis-flush: ## Flush all Redis keys (DEV ONLY)
	@docker compose exec redis redis-cli -a $(REDIS_PASSWORD) FLUSHALL
	@echo "Redis flushed."

# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Fly.io
# Prerequisites: brew install flyctl  OR  curl -L https://fly.io/install.sh | sh
# ─────────────────────────────────────────────────────────────────────────────

FLY_APP      := face-api
FLY_DB_APP   := face-api-db
FLY_REGION   := lhr

.PHONY: fly-auth
fly-auth: ## Authenticate with Fly.io
	@fly auth login

.PHONY: fly-setup
fly-setup: ## First-time Fly.io setup: create app and Postgres (Redis via Upstash.com)
	@echo "==> Creating API app..."
	@fly apps create $(FLY_APP) || true

	@echo ""
	@echo "==> Creating Postgres app (pgvector image)..."
	@fly apps create $(FLY_DB_APP) || true
	@fly volumes create pg_data \
		--app $(FLY_DB_APP) \
		--size 1 \
		--region $(FLY_REGION) || true

	@echo ""
	@echo "==> Redis: sign up free at https://upstash.com"
	@echo "   Create a Redis database, copy the 'Redis URL', then run:"
	@echo "   make fly-secrets"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Get Redis URL from https://upstash.com (free, no card needed)"
	@echo "  2. Set secrets:  make fly-secrets"
	@echo "  3. Deploy DB:    make fly-deploy-db"
	@echo "  4. Deploy API:   make fly-deploy"

.PHONY: fly-secrets
fly-secrets: ## Set all required Fly.io secrets (prompts interactively)
	@echo "==> Setting API secrets for $(FLY_APP)..."
	@echo "Paste your PASETO_SECRET (64 hex chars) and press Enter:"; \
		read PASETO; \
		fly secrets set PASETO_SECRET="$$PASETO" --app $(FLY_APP)
	@echo "Paste your DB password and press Enter:"; \
		read DBPASS; \
		fly secrets set \
			DB_URL="postgres://faceapi:$$DBPASS@$(FLY_DB_APP).internal:5432/faceapi?sslmode=disable" \
			--app $(FLY_APP); \
		fly secrets set POSTGRES_PASSWORD="$$DBPASS" --app $(FLY_DB_APP)
	@echo "Paste your Redis URL (from 'fly redis status') and press Enter:"; \
		read REDIS; \
		fly secrets set REDIS_URL="$$REDIS" --app $(FLY_APP)
	@echo "Secrets set."

.PHONY: fly-deploy-db
fly-deploy-db: ## Deploy the pgvector Postgres machine
	@echo "==> Deploying Postgres + pgvector..."
	@fly deploy --config fly.postgres.toml --app $(FLY_DB_APP)

.PHONY: fly-deploy
fly-deploy: ## Build and deploy the API to Fly.io
	@echo "==> Deploying $(FLY_APP)..."
	@fly deploy --config fly.toml --app $(FLY_APP)

.PHONY: fly-logs
fly-logs: ## Tail live logs from the API
	@fly logs --app $(FLY_APP)

.PHONY: fly-logs-db
fly-logs-db: ## Tail live logs from the Postgres machine
	@fly logs --app $(FLY_DB_APP)

.PHONY: fly-status
fly-status: ## Show status of the API and DB apps
	@echo "=== API ==="
	@fly status --app $(FLY_APP)
	@echo ""
	@echo "=== Postgres ==="
	@fly status --app $(FLY_DB_APP)

.PHONY: fly-ssh
fly-ssh: ## SSH into the running API machine
	@fly ssh console --app $(FLY_APP)

.PHONY: fly-db-shell
fly-db-shell: ## Open a psql shell on the Postgres machine via Fly proxy
	@fly proxy 15432:5432 --app $(FLY_DB_APP) & \
		sleep 2 && \
		psql "postgres://faceapi@localhost:15432/faceapi" ; \
		kill %1

.PHONY: fly-scale
fly-scale: ## Scale API to 2 machines (usage: make fly-scale COUNT=2)
	@fly scale count ${COUNT:-2} --app $(FLY_APP)

.PHONY: fly-secrets-list
fly-secrets-list: ## List secret names (values are hidden)
	@fly secrets list --app $(FLY_APP)

# ─────────────────────────────────────────────────────────────────────────────
# Setup
.PHONY: setup
setup: ## First-time setup: copy .env, create dirs, download models
	@[ -f .env ] || (cp .env.example .env && echo "Created .env from .env.example")
	@mkdir -p models logs bin coverage
	@echo ""
	@echo "Downloading face model files..."
	@$(MAKE) download-models
	@echo ""
	@echo "Setup complete. Run 'make up' to start."

.PHONY: download-models
download-models: ## Download dlib face model files into models/
	@mkdir -p models
	@echo "Downloading mmod_human_face_detector.dat..."
	@[ -f models/mmod_human_face_detector.dat ] || \
		(wget -q -O models/mmod_human_face_detector.dat.bz2 \
			http://dlib.net/files/mmod_human_face_detector.dat.bz2 && \
		bzip2 -d models/mmod_human_face_detector.dat.bz2)
	@echo "Downloading shape_predictor_5_face_landmarks.dat..."
	@[ -f models/shape_predictor_5_face_landmarks.dat ] || \
		(wget -q -O models/shape_predictor_5_face_landmarks.dat.bz2 \
			http://dlib.net/files/shape_predictor_5_face_landmarks.dat.bz2 && \
		bzip2 -d models/shape_predictor_5_face_landmarks.dat.bz2)
	@echo "Downloading dlib_face_recognition_resnet_model_v1.dat..."
	@[ -f models/dlib_face_recognition_resnet_model_v1.dat ] || \
		(wget -q -O models/dlib_face_recognition_resnet_model_v1.dat.bz2 \
			http://dlib.net/files/dlib_face_recognition_resnet_model_v1.dat.bz2 && \
		bzip2 -d models/dlib_face_recognition_resnet_model_v1.dat.bz2)
	@echo "All models ready in models/"