# Dependency Manager Agent

> Manage, audit, and update project dependencies across languages with real tools.

## Safety Rules

- NEVER force-update all dependencies at once in production projects
- NEVER ignore security vulnerabilities marked as critical or high severity
- NEVER remove lock files (package-lock.json, Pipfile.lock, go.sum, Cargo.lock) without understanding the consequences
- NEVER auto-merge dependency updates without checking changelogs for breaking changes
- Always test after updating dependencies
- Always review changelogs for major version bumps
- Always maintain lock files for reproducible builds

---

## Dependency Audit Tools

### npm (Node.js)
```bash
# Audit for vulnerabilities
npm audit
npm audit --json                    # JSON output
npm audit --production              # Only production deps
npm audit fix                       # Auto-fix where possible
npm audit fix --force               # Force fix (may include breaking changes)

# Detailed report
npm audit --audit-level=high        # Only show high/critical

# Check for outdated packages
npm outdated
npm outdated --long                 # Show type and homepage

# List installed packages
npm list --depth=0                  # Top-level only
npm list --all                      # Full tree
npm list --json                     # JSON format

# Check specific package
npm view express versions           # All versions
npm view express dist-tags          # Tags (latest, next)
npm info express                    # Full package info

# Find unused dependencies
npx depcheck
npx depcheck --ignores="eslint,prettier"

# Find duplicate packages
npx npm-dedupe
npm dedupe
```

### pip (Python)
```bash
# Install audit tools
pip3 install pip-audit safety

# Audit for vulnerabilities
pip-audit
pip-audit --fix                     # Auto-fix vulnerabilities
pip-audit -r requirements.txt       # Check requirements file
pip-audit --format json             # JSON output
pip-audit --desc                    # Show vulnerability descriptions

# Safety (alternative auditor)
safety check
safety check -r requirements.txt
safety check --full-report

# Check outdated packages
pip3 list --outdated
pip3 list --outdated --format=json

# Show dependency tree
pip3 install pipdeptree
pipdeptree
pipdeptree --reverse                # Show reverse dependencies
pipdeptree --warn silence           # Suppress warnings
pipdeptree -p requests              # Show tree for specific package

# Find unused imports/deps
pip3 install deptry
deptry .
```

### Go
```bash
# Tidy dependencies (remove unused, add missing)
go mod tidy
go mod tidy -v                      # Verbose

# Verify module checksums
go mod verify

# List all dependencies
go list -m all
go list -m -json all                # JSON format

# Check for updates
go list -m -u all                   # Show available updates
go list -m -u -json all             # JSON format

# Audit for vulnerabilities
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Show dependency graph
go mod graph
go mod graph | sed -Ee 's/@[^[:space:]]+//g' | sort -u

# Download dependencies
go mod download

# Vendor dependencies
go mod vendor
go mod vendor -v
```

### Rust (Cargo)
```bash
# Audit for vulnerabilities
cargo install cargo-audit
cargo audit
cargo audit fix                     # Auto-fix

# Check for outdated deps
cargo install cargo-outdated
cargo outdated
cargo outdated --root-deps-only     # Only direct dependencies

# List dependencies
cargo tree
cargo tree --depth 1                # Only direct deps
cargo tree --duplicates             # Show duplicate packages
cargo tree --invert regex           # Reverse tree for a package

# Update dependencies
cargo update                        # Update within semver ranges
cargo update -p package_name        # Update specific package

# Check unused deps
cargo install cargo-udeps
cargo +nightly udeps                # Requires nightly

# Generate lockfile
cargo generate-lockfile
```

### Snyk CLI (Multi-language)
```bash
# Install Snyk
npm install -g snyk

# Authenticate
snyk auth

# Test for vulnerabilities
snyk test
snyk test --all-projects            # Monorepo support
snyk test --severity-threshold=high # Only high+critical
snyk test --json                    # JSON output

# Monitor continuously
snyk monitor

# Fix vulnerabilities
snyk fix

# Test container images
snyk container test image:tag

# Test IaC files
snyk iac test terraform/
```

---

## Dependency Update Strategies

### Node.js Update Workflow
```bash
# Step 1: Check what's outdated
npm outdated

# Step 2: Update patch/minor versions (safe)
npm update

# Step 3: Check for major version updates
npx npm-check-updates
npx npm-check-updates -u --target minor    # Only minor updates
npx npm-check-updates -u --target patch    # Only patches

# Step 4: Interactive update
npx npm-check-updates --interactive

# Step 5: Update specific package to latest
npm install package@latest

# Step 6: Update all to latest (review carefully!)
npx npm-check-updates -u
npm install

# Step 7: Run tests
npm test

# Step 8: Check for breaking changes
npm audit
```

### Python Update Workflow
```bash
# Step 1: Check outdated
pip3 list --outdated

# Step 2: Update specific package
pip3 install --upgrade package_name

# Step 3: Update all packages (be careful)
pip3 list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip3 install --upgrade

# Step 4: Regenerate requirements
pip3 freeze > requirements.txt

# Step 5: Or use pip-compile for pinning
pip3 install pip-tools
pip-compile requirements.in           # Generate pinned requirements.txt
pip-compile --upgrade requirements.in # Upgrade all
pip-sync requirements.txt             # Sync environment

# Step 6: Run tests
pytest
```

### Go Update Workflow
```bash
# Step 1: Check for updates
go list -m -u all

# Step 2: Update specific dependency
go get -u github.com/pkg/name@latest
go get github.com/pkg/name@v1.2.3    # Specific version

# Step 3: Update all dependencies
go get -u ./...

# Step 4: Clean up
go mod tidy

# Step 5: Verify
go mod verify

# Step 6: Run tests
go test ./...
```

---

## Lock File Management

### Understanding Lock Files
```
package-lock.json  — npm (Node.js)
yarn.lock          — Yarn (Node.js)
pnpm-lock.yaml     — pnpm (Node.js)
Pipfile.lock       — Pipenv (Python)
poetry.lock        — Poetry (Python)
go.sum             — Go modules
Cargo.lock         — Cargo (Rust)
composer.lock      — Composer (PHP)
Gemfile.lock       — Bundler (Ruby)
```

### Lock File Best Practices
```bash
# Always commit lock files for applications
# Do NOT commit lock files for libraries (except Cargo.lock)

# Regenerate lock file from scratch (Node.js)
rm -f package-lock.json && npm install

# Verify lock file integrity
npm ci                                    # Install exactly from lock file (CI)
pip install --require-hashes -r req.txt   # Verify hashes (Python)
go mod verify                             # Verify checksums (Go)

# Install from lock file (deterministic)
npm ci                    # Node.js
pip install -r requirements.txt   # Python
go mod download           # Go
cargo build               # Rust (uses Cargo.lock)
```

---

## Dependency Tree Analysis

### Visualize Dependencies
```bash
# Node.js
npm list --all --depth=3
npx npm-remote-ls package_name     # Remote package tree

# Visualize as graph
npx madge --image deps.svg src/    # Source code deps
npx npm-dependency-tree > tree.txt # npm dependency tree

# Python
pipdeptree
pipdeptree --graph-output png > deps.png
pipdeptree -p package_name

# Go
go mod graph | head -50

# Rust
cargo tree
cargo tree --prefix depth
```

### Find Duplicate Dependencies
```bash
# Node.js
npm dedupe --dry-run
npx find-duplicate-dependencies

# Check bundle size impact
npx bundlephobia-cli package_name

# Rust
cargo tree --duplicates
```

### Analyze Bundle Size (JavaScript)
```bash
# Analyze webpack bundle
npx webpack-bundle-analyzer stats.json

# Check import cost
npx import-cost

# Check package size before installing
npx bundlephobia-cli express
npx package-size express lodash axios
```

---

## Automated Dependency Updates

### Renovate Configuration
```json
// renovate.json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "config:recommended",
    ":automergeMinor",
    ":automergeDigest"
  ],
  "labels": ["dependencies"],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security"]
  },
  "packageRules": [
    {
      "matchUpdateTypes": ["major"],
      "labels": ["major-update"],
      "automerge": false
    },
    {
      "matchUpdateTypes": ["minor", "patch"],
      "automerge": true,
      "automergeType": "branch"
    },
    {
      "groupName": "linters",
      "matchPackageNames": ["eslint", "prettier", "ruff"],
      "automerge": true
    },
    {
      "groupName": "test dependencies",
      "matchDepTypes": ["devDependencies"],
      "matchPackagePatterns": ["jest", "testing", "vitest"],
      "automerge": true
    }
  ],
  "schedule": ["after 9am and before 5pm on Monday"]
}
```

### Dependabot Configuration
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    reviewers:
      - "team-name"
    labels:
      - "dependencies"
    groups:
      development-dependencies:
        dependency-type: "development"
        update-types: ["minor", "patch"]
      production-dependencies:
        dependency-type: "production"
        update-types: ["patch"]

  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"

  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
```

---

## Security Scanning in CI

### GitHub Actions Security Workflow
```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 8 * * 1'  # Weekly Monday 8am

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Node.js audit
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm audit --audit-level=high

      # Python audit
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install pip-audit
      - run: pip-audit -r requirements.txt

      # Snyk scan
      - uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

---

## Package Manager Configuration

### .npmrc (Node.js)
```ini
# .npmrc
engine-strict=true
save-exact=true
package-lock=true
audit-level=moderate
fund=false
```

### pip.conf (Python)
```ini
# ~/.config/pip/pip.conf
[global]
require-virtualenv = true
no-cache-dir = false

[install]
require-hashes = false
```

### Cargo Configuration (Rust)
```toml
# .cargo/config.toml
[net]
retry = 3

[build]
jobs = 4

[term]
verbose = false
color = "auto"
```

---

## Workflows

### Security Audit Workflow
1. Run language-specific audit: `npm audit` / `pip-audit` / `govulncheck` / `cargo audit`
2. Review critical and high severity vulnerabilities
3. Check if fixes are available
4. Apply fixes: `npm audit fix` / `pip-audit --fix` / `cargo audit fix`
5. For unfixable issues, evaluate risk and create tracking tickets
6. Run tests to ensure fixes don't break anything
7. Update lock files
8. Commit changes

### Dependency Update Workflow
1. Create a feature branch: `git checkout -b deps/update-YYYY-MM`
2. Check outdated packages
3. Update patch versions first (safest)
4. Run tests after each batch of updates
5. Update minor versions, checking changelogs
6. Update major versions one-at-a-time, reading migration guides
7. Run full test suite
8. Update lock files
9. Create PR for review

### New Project Dependency Setup
1. Choose package manager
2. Initialize config file (package.json, pyproject.toml, go.mod, Cargo.toml)
3. Add core dependencies
4. Add dev dependencies (linters, formatters, test frameworks)
5. Generate lock file
6. Set up automated updates (Renovate or Dependabot)
7. Configure security scanning in CI
8. Document dependency management policy in contributing guide
