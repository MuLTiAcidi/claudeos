# Code Generator Agent

> Scaffold projects, boilerplate code, and modules with real working templates and commands.

## Safety Rules

- NEVER overwrite existing project files without explicit confirmation
- NEVER commit generated code automatically — let the user review first
- NEVER include hardcoded secrets, passwords, or API keys in generated files
- ALWAYS check if a directory exists before scaffolding into it
- ALWAYS use the latest stable versions of dependencies unless specified otherwise
- NEVER run `rm -rf` on any directory

---

## Project Detection

Before scaffolding, detect existing project context:

```bash
# Check if directory is empty
ls -la /path/to/project/

# Detect existing project type
test -f package.json && echo "Node.js project detected"
test -f requirements.txt && echo "Python project detected"
test -f go.mod && echo "Go project detected"
test -f Cargo.toml && echo "Rust project detected"
test -f pom.xml && echo "Java/Maven project detected"
test -f build.gradle && echo "Java/Gradle project detected"
test -f composer.json && echo "PHP project detected"

# Check git status
git status 2>/dev/null || echo "Not a git repository"
```

---

## Node.js Project Scaffolding

### Express REST API

```bash
# Create project structure
mkdir -p myproject/{src/{routes,controllers,middleware,models,services,utils,config},tests/{unit,integration},docs}

# Initialize package.json
cd myproject && cat > package.json << 'PKGJSON'
{
  "name": "myproject",
  "version": "1.0.0",
  "description": "",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "jest --coverage",
    "test:watch": "jest --watch",
    "lint": "eslint src/ --ext .js,.ts",
    "lint:fix": "eslint src/ --ext .js,.ts --fix",
    "format": "prettier --write 'src/**/*.{js,ts,json}'"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0",
    "dotenv": "^16.3.1",
    "express-rate-limit": "^7.1.4",
    "express-validator": "^7.0.1",
    "winston": "^3.11.0"
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "nodemon": "^3.0.2",
    "eslint": "^8.55.0",
    "prettier": "^3.1.1"
  }
}
PKGJSON

# Create main entry point
cat > src/index.js << 'INDEXJS'
require('dotenv').config();
const app = require('./app');
const logger = require('./utils/logger');

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
INDEXJS

# Create Express app
cat > src/app.js << 'APPJS'
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const routes = require('./routes');
const errorHandler = require('./middleware/errorHandler');

const app = express();

app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use('/api', routes);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use(errorHandler);

module.exports = app;
APPJS

# Create error handler middleware
cat > src/middleware/errorHandler.js << 'ERRHANDLER'
const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  logger.error(err.stack);

  const status = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  res.status(status).json({
    error: {
      message,
      status,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
    },
  });
};

module.exports = errorHandler;
ERRHANDLER

# Create logger utility
cat > src/utils/logger.js << 'LOGGER'
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'myproject' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    ),
  }));
}

module.exports = logger;
LOGGER

# Create routes index
cat > src/routes/index.js << 'ROUTES'
const express = require('express');
const router = express.Router();

// Import route modules here
// const usersRouter = require('./users');
// router.use('/users', usersRouter);

router.get('/', (req, res) => {
  res.json({ message: 'API is running' });
});

module.exports = router;
ROUTES

# Create .env template
cat > .env.example << 'ENVEX'
NODE_ENV=development
PORT=3000
LOG_LEVEL=info
DATABASE_URL=
JWT_SECRET=
ENVEX

# Create .gitignore
cat > .gitignore << 'GITIGNORE'
node_modules/
dist/
.env
logs/
coverage/
*.log
.DS_Store
GITIGNORE

# Create .eslintrc.json
cat > .eslintrc.json << 'ESLINT'
{
  "env": {
    "node": true,
    "es2021": true,
    "jest": true
  },
  "extends": "eslint:recommended",
  "parserOptions": {
    "ecmaVersion": "latest"
  },
  "rules": {
    "no-unused-vars": ["warn", { "argsIgnorePattern": "^_" }],
    "no-console": "warn"
  }
}
ESLINT

# Install dependencies
npm install
```

### TypeScript Node.js Project

```bash
mkdir -p myproject/{src/{routes,controllers,middleware,models,services,utils,config,types},tests/{unit,integration}}

cd myproject && npm init -y

# Install TypeScript dependencies
npm install typescript ts-node @types/node --save-dev
npm install @types/express --save-dev

# Generate tsconfig.json
npx tsc --init --rootDir src --outDir dist --esModuleInterop --resolveJsonModule --lib es2021 --module commonjs --allowJs true --noImplicitAny true --strict true --sourceMap true

# Or create manually
cat > tsconfig.json << 'TSCONFIG'
{
  "compilerOptions": {
    "target": "ES2021",
    "module": "commonjs",
    "lib": ["ES2021"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
TSCONFIG
```

### Next.js Project

```bash
npx create-next-app@latest myproject --typescript --tailwind --eslint --app --src-dir --import-alias "@/*"
```

---

## Python Project Scaffolding

### Flask/FastAPI REST API

```bash
# Create project structure
mkdir -p myproject/{app/{api/{v1,v2},models,schemas,services,utils,middleware,core},tests/{unit,integration,fixtures},migrations,docs,scripts}

cd myproject

# Create pyproject.toml
cat > pyproject.toml << 'PYPROJECT'
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "myproject"
version = "0.1.0"
description = ""
requires-python = ">=3.10"
dependencies = [
    "fastapi>=0.104.0",
    "uvicorn[standard]>=0.24.0",
    "pydantic>=2.5.0",
    "pydantic-settings>=2.1.0",
    "sqlalchemy>=2.0.23",
    "alembic>=1.13.0",
    "python-dotenv>=1.0.0",
    "httpx>=0.25.2",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.3",
    "pytest-cov>=4.1.0",
    "pytest-asyncio>=0.23.0",
    "black>=23.12.0",
    "ruff>=0.1.8",
    "mypy>=1.7.0",
    "pre-commit>=3.6.0",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"

[tool.black]
line-length = 88

[tool.ruff]
line-length = 88
select = ["E", "F", "I", "N", "W", "UP"]

[tool.mypy]
python_version = "3.10"
strict = true
PYPROJECT

# Create requirements.txt (for compatibility)
cat > requirements.txt << 'REQS'
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
pydantic>=2.5.0
pydantic-settings>=2.1.0
sqlalchemy>=2.0.23
alembic>=1.13.0
python-dotenv>=1.0.0
httpx>=0.25.2
REQS

cat > requirements-dev.txt << 'REQSDEV'
-r requirements.txt
pytest>=7.4.3
pytest-cov>=4.1.0
pytest-asyncio>=0.23.0
black>=23.12.0
ruff>=0.1.8
mypy>=1.7.0
pre-commit>=3.6.0
REQSDEV

# Create main FastAPI app
cat > app/__init__.py << 'INIT'
INIT

cat > app/main.py << 'MAIN'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1 import router as v1_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(v1_router, prefix="/api/v1")

@app.get("/health")
async def health_check():
    return {"status": "ok"}
MAIN

# Create config
cat > app/core/__init__.py << 'INIT'
INIT

cat > app/core/config.py << 'CONFIG'
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "myproject"
    VERSION: str = "0.1.0"
    DEBUG: bool = False
    DATABASE_URL: str = "sqlite:///./app.db"
    ALLOWED_ORIGINS: List[str] = ["*"]
    SECRET_KEY: str = "change-me-in-production"

    class Config:
        env_file = ".env"

settings = Settings()
CONFIG

# Create virtual environment and install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

### Python CLI Tool

```bash
mkdir -p myproject/{src/myproject,tests}

cd myproject

cat > pyproject.toml << 'PYPROJECT'
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "myproject"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "click>=8.1.7",
    "rich>=13.7.0",
]

[project.scripts]
myproject = "myproject.cli:main"
PYPROJECT

cat > src/myproject/__init__.py << 'INIT'
__version__ = "0.1.0"
INIT

cat > src/myproject/cli.py << 'CLI'
import click
from rich.console import Console

console = Console()

@click.group()
@click.version_option()
def main():
    """My CLI tool description."""
    pass

@main.command()
@click.argument("name")
def hello(name: str):
    """Say hello to NAME."""
    console.print(f"[green]Hello, {name}![/green]")

if __name__ == "__main__":
    main()
CLI
```

---

## Go Project Scaffolding

### Go REST API

```bash
mkdir -p myproject/{cmd/server,internal/{handlers,middleware,models,repository,services,config},pkg/utils,api,migrations,tests}

cd myproject

# Initialize Go module
go mod init github.com/username/myproject

# Create main.go
cat > cmd/server/main.go << 'MAINGO'
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/username/myproject/internal/config"
	"github.com/username/myproject/internal/handlers"
)

func main() {
	cfg := config.Load()

	router := handlers.NewRouter(cfg)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Server starting on port %s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exited")
}
MAINGO

# Create config
cat > internal/config/config.go << 'CONFIGGO'
package config

import "os"

type Config struct {
	Port        string
	DatabaseURL string
	Environment string
}

func Load() *Config {
	return &Config{
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: getEnv("DATABASE_URL", ""),
		Environment: getEnv("ENVIRONMENT", "development"),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
CONFIGGO

# Install dependencies
go mod tidy
```

### Go CLI Tool

```bash
mkdir -p myproject/{cmd/myproject,internal/{commands,config},pkg}

cd myproject && go mod init github.com/username/myproject

cat > cmd/myproject/main.go << 'MAINGO'
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "myproject",
	Short: "A brief description",
	Long:  "A longer description of the tool.",
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
MAINGO

go get github.com/spf13/cobra@latest
go mod tidy
```

---

## Rust Project Scaffolding

### Rust CLI Application

```bash
cargo new myproject
cd myproject

# Add dependencies to Cargo.toml
cat > Cargo.toml << 'CARGO'
[package]
name = "myproject"
version = "0.1.0"
edition = "2021"
description = ""
license = "MIT"

[dependencies]
clap = { version = "4.4", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.35", features = ["full"] }
anyhow = "1.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
assert_cmd = "2.0"
predicates = "3.0"

[profile.release]
opt-level = 3
lto = true
strip = true
CARGO

cat > src/main.rs << 'MAINRS'
use clap::Parser;
use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name to greet
    #[arg(short, long)]
    name: String,

    /// Number of times to greet
    #[arg(short, long, default_value_t = 1)]
    count: u8,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    for _ in 0..args.count {
        println!("Hello, {}!", args.name);
    }

    Ok(())
}
MAINRS

cargo build
```

### Rust Web API (Actix-web)

```bash
cargo new myproject
cd myproject

cat > Cargo.toml << 'CARGO'
[package]
name = "myproject"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
actix-cors = "0.7"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.35", features = ["full"] }
sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "postgres"] }
tracing = "0.1"
tracing-subscriber = "0.3"
tracing-actix-web = "0.7"
dotenv = "0.15"
anyhow = "1.0"
CARGO
```

---

## Dockerfile Generation

### Node.js Dockerfile

```bash
cat > Dockerfile << 'DOCKERFILE'
FROM node:20-alpine AS base

WORKDIR /app

FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --only=production

FROM base AS build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM base AS production
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 appuser
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
USER appuser
EXPOSE 3000
CMD ["node", "dist/index.js"]
DOCKERFILE

cat > .dockerignore << 'DIGNORE'
node_modules
npm-debug.log
Dockerfile
.dockerignore
.git
.gitignore
.env
coverage
tests
docs
*.md
DIGNORE
```

### Python Dockerfile

```bash
cat > Dockerfile << 'DOCKERFILE'
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

FROM base AS deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS production
RUN groupadd --system appgroup && \
    useradd --system --gid appgroup appuser

COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin
COPY . .

USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
DOCKERFILE
```

### Go Dockerfile

```bash
cat > Dockerfile << 'DOCKERFILE'
FROM golang:1.22-alpine AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server ./cmd/server

FROM alpine:3.19 AS production
RUN apk --no-cache add ca-certificates tzdata && \
    adduser -D -g '' appuser
COPY --from=build /server /server
USER appuser
EXPOSE 8080
ENTRYPOINT ["/server"]
DOCKERFILE
```

---

## CI/CD Configuration Scaffolding

### GitHub Actions

```bash
mkdir -p .github/workflows

# Node.js CI
cat > .github/workflows/ci.yml << 'GHACI'
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18, 20]
    steps:
      - uses: actions/checkout@v4
      - name: Use Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm test
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        if: matrix.node-version == 20

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci
      - run: npm run build

  docker:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max
GHACI

# Python CI
cat > .github/workflows/python-ci.yml << 'PYCI'
name: Python CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: 'pip'
      - run: pip install -r requirements-dev.txt
      - run: ruff check .
      - run: mypy app/
      - run: pytest --cov=app --cov-report=xml
      - uses: codecov/codecov-action@v3
PYCI
```

### GitLab CI

```bash
cat > .gitlab-ci.yml << 'GLCI'
stages:
  - test
  - build
  - deploy

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip
    - node_modules/

test:
  stage: test
  image: node:20-alpine
  script:
    - npm ci
    - npm run lint
    - npm test -- --coverage
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main
GLCI
```

---

## Docker Compose Generation

```bash
cat > docker-compose.yml << 'COMPOSE'
version: "3.8"

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgres://postgres:postgres@db:5432/myproject
      - REDIS_URL=redis://redis:6379
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
    volumes:
      - .:/app
      - /app/node_modules
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: myproject
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redisdata:/data

volumes:
  pgdata:
  redisdata:
COMPOSE
```

---

## Makefile Generation

```bash
cat > Makefile << 'MAKEFILE'
.PHONY: help build run test lint clean docker-build docker-run

BINARY_NAME=myproject
DOCKER_IMAGE=myproject

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the project
	go build -o bin/$(BINARY_NAME) ./cmd/server

run: ## Run the project
	go run ./cmd/server

test: ## Run tests
	go test -v -race -coverprofile=coverage.out ./...

lint: ## Run linter
	golangci-lint run ./...

clean: ## Clean build artifacts
	rm -f bin/$(BINARY_NAME)
	rm -f coverage.out

docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE) .

docker-run: ## Run Docker container
	docker run -p 8080:8080 $(DOCKER_IMAGE)

migrate-up: ## Run database migrations
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down: ## Rollback database migrations
	migrate -path migrations -database "$(DATABASE_URL)" down 1

migrate-create: ## Create a new migration (usage: make migrate-create name=create_users)
	migrate create -ext sql -dir migrations -seq $(name)
MAKEFILE
```

---

## EditorConfig and Prettier

```bash
# EditorConfig
cat > .editorconfig << 'EDITORCONFIG'
root = true

[*]
indent_style = space
indent_size = 2
end_of_line = lf
charset = utf-8
trim_trailing_whitespace = true
insert_final_newline = true

[*.{py,go,rs}]
indent_size = 4

[Makefile]
indent_style = tab
EDITORCONFIG

# Prettier config
cat > .prettierrc << 'PRETTIER'
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false
}
PRETTIER

cat > .prettierignore << 'PIGNORE'
node_modules
dist
build
coverage
*.min.js
PIGNORE
```

---

## Pre-commit Hooks

```bash
# Using husky for Node.js
npx husky-init && npm install
npx husky set .husky/pre-commit "npm run lint && npm test"
npx husky set .husky/commit-msg 'npx commitlint --edit "$1"'

# commitlint config
cat > commitlint.config.js << 'COMMITLINT'
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', [
      'feat', 'fix', 'docs', 'style', 'refactor',
      'perf', 'test', 'build', 'ci', 'chore', 'revert',
    ]],
    'subject-max-length': [2, 'always', 72],
  },
};
COMMITLINT

npm install @commitlint/cli @commitlint/config-conventional --save-dev

# Using pre-commit for Python
cat > .pre-commit-config.yaml << 'PRECOMMIT'
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-added-large-files
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.8
    hooks:
      - id: ruff
        args: [--fix]
  - repo: https://github.com/psf/black
    rev: 23.12.0
    hooks:
      - id: black
PRECOMMIT

pre-commit install
```

---

## Scaffolding Workflow

1. Ask the user: language, framework, project name, features needed
2. Create directory structure with `mkdir -p`
3. Generate config files (package.json, pyproject.toml, go.mod, Cargo.toml)
4. Generate boilerplate source files
5. Generate Dockerfile and .dockerignore
6. Generate CI configuration
7. Generate .gitignore, .editorconfig, linter configs
8. Initialize git repository: `git init && git add . && git commit -m "Initial scaffold"`
9. Install dependencies if requested
10. Report what was generated and suggest next steps
