# Doc Generator Agent

> Auto-generate code documentation, API docs, changelogs, and man pages using real tools.

## Safety Rules

- NEVER overwrite existing documentation without confirmation
- NEVER expose internal implementation details meant to be private in public docs
- NEVER include secrets, credentials, or PII in generated documentation
- NEVER generate misleading or inaccurate documentation
- Always preserve existing hand-written documentation sections
- Always verify generated docs build without errors
- Always include version information in generated documentation

---

## Documentation Tool Installation

```bash
# Python
pip3 install sphinx sphinx-rtd-theme sphinx-autodoc-typehints myst-parser pdoc pydoc-markdown mkdocs mkdocs-material

# JavaScript/TypeScript
npm install -g jsdoc typedoc documentation

# Go
go install golang.org/x/tools/cmd/godoc@latest

# Rust (rustdoc is built-in)
rustup component add rust-docs

# General
sudo apt-get install -y doxygen graphviz pandoc
pip3 install grip          # Markdown preview

# Changelog tools
npm install -g conventional-changelog-cli auto-changelog
pip3 install towncrier
```

---

## Python Documentation

### Sphinx Setup
```bash
# Initialize Sphinx project
mkdir -p docs
cd docs
sphinx-quickstart --sep --project "My Project" --author "Author" --release "1.0.0" --language "en" --ext-autodoc --ext-viewcode --ext-todo

# Or non-interactive
sphinx-quickstart docs \
  --sep \
  --project "My Project" \
  --author "Author" \
  -v "1.0.0" \
  --ext-autodoc \
  --ext-viewcode \
  --ext-intersphinx \
  --ext-todo \
  --no-batchfile \
  --makefile
```

### Sphinx Configuration
```python
# docs/source/conf.py
import os
import sys
sys.path.insert(0, os.path.abspath('../../src'))

project = 'My Project'
copyright = '2024, Author'
author = 'Author'
release = '1.0.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',           # Google/NumPy style docstrings
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'sphinx_autodoc_typehints',      # Type hints in docs
    'myst_parser',                    # Markdown support
]

templates_path = ['_templates']
exclude_patterns = []

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Napoleon settings (Google-style docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True

# Autodoc settings
autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'special-members': '__init__',
    'undoc-members': True,
    'show-inheritance': True,
}
autodoc_typehints = 'description'

# Intersphinx mapping
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
}

# Source suffix
source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}
```

### Generate API Docs Automatically
```bash
# Auto-generate rst files from Python modules
sphinx-apidoc -f -o docs/source/api src/mypackage --separate --module-first

# Build HTML docs
cd docs && make html

# Build and serve
cd docs && make html && python3 -m http.server 8000 --directory build/html
```

### Python Docstring Formats

```python
# Google-style docstring (recommended)
def create_user(email: str, name: str, role: str = "user") -> dict:
    """Create a new user account.

    Creates a user with the given email and name. The email must be unique
    across all users in the system.

    Args:
        email: The user's email address. Must be a valid email format.
        name: The user's display name. Must be 1-100 characters.
        role: The user's role. Defaults to "user".
            Valid values: "user", "admin", "moderator".

    Returns:
        A dictionary containing the created user data::

            {
                "id": "uuid-string",
                "email": "user@example.com",
                "name": "User Name",
                "role": "user",
                "created_at": "2024-01-01T00:00:00Z"
            }

    Raises:
        ValueError: If the email is already registered.
        ValidationError: If the email format is invalid.

    Example:
        >>> user = create_user("test@example.com", "Test User")
        >>> print(user["id"])
        'uuid-123'

    Note:
        Passwords are hashed using bcrypt before storage.
    """
    pass


# NumPy-style docstring
def calculate_statistics(data: list[float]) -> dict:
    """
    Calculate descriptive statistics for a dataset.

    Parameters
    ----------
    data : list of float
        The input data values. Must contain at least one element.

    Returns
    -------
    dict
        A dictionary with keys 'mean', 'median', 'std', 'min', 'max'.

    Raises
    ------
    ValueError
        If data is empty.

    Examples
    --------
    >>> calculate_statistics([1.0, 2.0, 3.0])
    {'mean': 2.0, 'median': 2.0, 'std': 0.816, 'min': 1.0, 'max': 3.0}
    """
    pass
```

### pdoc (Alternative Python Doc Generator)
```bash
# Generate HTML docs
pdoc --html --output-dir docs/api src/mypackage

# Serve live
pdoc --http : src/mypackage

# Generate Markdown
pdoc --output-dir docs/api src/mypackage --format md
```

### MkDocs (Markdown-based)
```bash
# Initialize
mkdocs new my-docs
cd my-docs

# Configure
cat > mkdocs.yml << 'MKDOCS'
site_name: My Project
site_description: Project documentation
theme:
  name: material
  palette:
    primary: indigo
    accent: indigo
  features:
    - navigation.tabs
    - navigation.sections
    - search.suggest
    - content.code.copy

plugins:
  - search
  - mkdocstrings:
      handlers:
        python:
          options:
            show_source: true
            show_root_heading: true

nav:
  - Home: index.md
  - Getting Started:
    - Installation: getting-started/installation.md
    - Quick Start: getting-started/quickstart.md
  - API Reference:
    - Overview: api/overview.md
  - Contributing: contributing.md

markdown_extensions:
  - pymdownx.highlight
  - pymdownx.superfences
  - pymdownx.tabbed:
      alternate_style: true
  - admonition
  - def_list
  - attr_list
MKDOCS

# Build
mkdocs build

# Serve locally
mkdocs serve

# Deploy to GitHub Pages
mkdocs gh-deploy
```

---

## JavaScript/TypeScript Documentation

### JSDoc
```bash
# Install
npm install --save-dev jsdoc

# Configuration
cat > jsdoc.json << 'JSDOC'
{
  "source": {
    "include": ["src/"],
    "includePattern": ".+\\.js(x)?$",
    "excludePattern": "(node_modules|docs|tests)"
  },
  "opts": {
    "destination": "./docs/api",
    "recurse": true,
    "readme": "./README.md",
    "template": "node_modules/clean-jsdoc-theme"
  },
  "plugins": ["plugins/markdown"],
  "templates": {
    "cleverLinks": true,
    "monospaceLinks": false
  }
}
JSDOC

npm install --save-dev clean-jsdoc-theme

# Generate docs
npx jsdoc -c jsdoc.json
```

### JSDoc Annotations
```javascript
/**
 * User service for managing user accounts.
 * @module UserService
 */

/**
 * Represents a user in the system.
 * @typedef {Object} User
 * @property {string} id - Unique identifier (UUID).
 * @property {string} email - User's email address.
 * @property {string} name - User's display name.
 * @property {('user'|'admin'|'moderator')} role - User's role.
 * @property {Date} createdAt - Account creation timestamp.
 */

/**
 * Creates a new user account.
 *
 * @async
 * @param {Object} userData - The user data.
 * @param {string} userData.email - Email address (must be unique).
 * @param {string} userData.name - Display name (1-100 characters).
 * @param {string} userData.password - Password (min 8 characters).
 * @param {string} [userData.role='user'] - Optional role assignment.
 * @returns {Promise<User>} The created user object.
 * @throws {ValidationError} If the input data is invalid.
 * @throws {ConflictError} If the email is already registered.
 *
 * @example
 * const user = await createUser({
 *   email: 'new@example.com',
 *   name: 'New User',
 *   password: 'securePass123',
 * });
 * console.log(user.id); // 'uuid-123'
 */
async function createUser(userData) {
  // ...
}
```

### TypeDoc (TypeScript)
```bash
# Install
npm install --save-dev typedoc

# Configuration
cat > typedoc.json << 'TYPEDOC'
{
  "entryPoints": ["src/index.ts"],
  "entryPointStrategy": "expand",
  "out": "docs/api",
  "name": "My Project",
  "includeVersion": true,
  "readme": "README.md",
  "theme": "default",
  "excludePrivate": true,
  "excludeProtected": false,
  "excludeInternal": true,
  "plugin": ["typedoc-plugin-markdown"],
  "gitRevision": "main"
}
TYPEDOC

# Generate docs
npx typedoc

# Generate Markdown instead of HTML
npm install --save-dev typedoc-plugin-markdown
npx typedoc --plugin typedoc-plugin-markdown
```

---

## Go Documentation

### godoc
```bash
# Serve docs locally
godoc -http=:6060
# Browse http://localhost:6060/pkg/github.com/org/project/

# Generate static HTML
go install golang.org/x/tools/cmd/godoc@latest
godoc -url="/pkg/github.com/org/project/" > docs/api.html
```

### Go Doc Comments
```go
// Package users provides user management functionality.
//
// This package handles creating, reading, updating, and deleting
// user accounts. All operations require proper authentication.
//
// # Getting Started
//
// Create a new UserService with the required dependencies:
//
//	repo := NewPostgresRepository(db)
//	service := NewUserService(repo)
//
// # Examples
//
// Creating a user:
//
//	user, err := service.Create(ctx, CreateUserInput{
//	    Email: "user@example.com",
//	    Name:  "Test User",
//	})
package users

// UserService handles user-related business logic.
//
// It requires a UserRepository for data access and supports
// concurrent access from multiple goroutines.
type UserService struct {
    repo UserRepository
}

// NewUserService creates a new UserService with the given repository.
//
// The repository must not be nil, otherwise NewUserService panics.
func NewUserService(repo UserRepository) *UserService {
    if repo == nil {
        panic("repository must not be nil")
    }
    return &UserService{repo: repo}
}

// GetUser retrieves a user by their unique identifier.
//
// It returns ErrNotFound if no user exists with the given ID.
//
// Example:
//
//	user, err := service.GetUser(ctx, "uuid-123")
//	if errors.Is(err, ErrNotFound) {
//	    // handle not found
//	}
func (s *UserService) GetUser(ctx context.Context, id string) (*User, error) {
    return s.repo.GetByID(ctx, id)
}
```

```bash
# View docs from command line
go doc github.com/org/project/pkg
go doc github.com/org/project/pkg.FunctionName
go doc -all github.com/org/project/pkg
```

---

## Rust Documentation

### rustdoc
```bash
# Generate documentation
cargo doc --open
cargo doc --no-deps                # Skip dependencies
cargo doc --document-private-items # Include private items

# Test doc examples
cargo test --doc
```

### Rust Doc Comments
```rust
//! # My Crate
//!
//! `my_crate` provides utilities for user management.
//!
//! ## Quick Start
//!
//! ```rust
//! use my_crate::UserService;
//!
//! let service = UserService::new();
//! let user = service.create_user("test@example.com", "Test").unwrap();
//! ```

/// A user in the system.
///
/// Users are identified by a unique UUID and must have a valid email.
///
/// # Examples
///
/// ```
/// use my_crate::User;
///
/// let user = User::new("test@example.com", "Test User");
/// assert_eq!(user.email(), "test@example.com");
/// ```
pub struct User {
    /// The user's unique identifier.
    id: Uuid,
    /// The user's email address.
    email: String,
    /// The user's display name.
    name: String,
}

/// Creates a new user with the given email and name.
///
/// # Arguments
///
/// * `email` - A valid email address (must contain '@')
/// * `name` - The display name (1-100 characters)
///
/// # Returns
///
/// A `Result` containing the new `User` or an error.
///
/// # Errors
///
/// Returns `ValidationError` if the email format is invalid.
///
/// # Panics
///
/// Panics if the name is empty (use `try_new` for fallible creation).
///
/// # Examples
///
/// ```
/// let user = User::new("test@example.com", "Test User").unwrap();
/// assert_eq!(user.name(), "Test User");
/// ```
///
/// ```should_panic
/// // This will panic because the name is empty
/// let user = User::new("test@example.com", "");
/// ```
pub fn new(email: &str, name: &str) -> Result<Self, ValidationError> {
    // ...
}
```

---

## Doxygen (C/C++)

### Doxygen Setup
```bash
# Generate config file
doxygen -g Doxyfile

# Key settings in Doxyfile
cat > Doxyfile << 'DOXYFILE'
PROJECT_NAME           = "My Project"
PROJECT_NUMBER         = "1.0.0"
OUTPUT_DIRECTORY       = docs/api
INPUT                  = src/ include/
RECURSIVE              = YES
EXTRACT_ALL            = YES
EXTRACT_PRIVATE        = NO
EXTRACT_STATIC         = YES
FILE_PATTERNS          = *.c *.h *.cpp *.hpp
GENERATE_HTML          = YES
GENERATE_LATEX         = NO
GENERATE_XML           = YES
HTML_OUTPUT            = html
HAVE_DOT               = YES
CALL_GRAPH             = YES
CALLER_GRAPH           = YES
CLASS_DIAGRAMS         = YES
SOURCE_BROWSER         = YES
INLINE_SOURCES         = NO
OPTIMIZE_OUTPUT_FOR_C  = YES
DOXYFILE

# Generate docs
doxygen Doxyfile
```

### Doxygen Comment Style
```c
/**
 * @file user.h
 * @brief User management functions.
 * @author Author Name
 * @version 1.0
 * @date 2024-01-01
 */

/**
 * @brief Creates a new user account.
 *
 * Allocates and initializes a new User structure with the given
 * email and name. The caller is responsible for freeing the
 * returned pointer with user_free().
 *
 * @param email The user's email address (must not be NULL).
 * @param name The user's display name (must not be NULL).
 * @return Pointer to the new User, or NULL on failure.
 *
 * @note Thread-safe. Uses internal mutex for synchronization.
 * @warning The returned pointer must be freed with user_free().
 *
 * @code
 * User *user = user_create("test@example.com", "Test User");
 * if (user != NULL) {
 *     printf("Created user: %s\n", user->name);
 *     user_free(user);
 * }
 * @endcode
 *
 * @see user_free
 * @see user_update
 */
User *user_create(const char *email, const char *name);
```

---

## Changelog Generation

### Conventional Changelog
```bash
# Install
npm install -g conventional-changelog-cli

# Generate changelog
conventional-changelog -p angular -i CHANGELOG.md -s

# First release
conventional-changelog -p angular -i CHANGELOG.md -s -r 0

# All releases
conventional-changelog -p angular -i CHANGELOG.md -s -r 0
```

### Conventional Commit Format
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]

Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert

Examples:
feat(auth): add OAuth2 login support
fix(api): handle null response from external service
docs: update API endpoint documentation
BREAKING CHANGE: rename /api/users to /api/v2/users
```

### auto-changelog
```bash
npm install -g auto-changelog

# Generate from git history
auto-changelog

# With options
auto-changelog --output CHANGELOG.md --template keepachangelog --commit-limit false --unreleased

# Configuration in package.json
# "auto-changelog": {
#   "output": "CHANGELOG.md",
#   "template": "keepachangelog",
#   "unreleased": true,
#   "commitLimit": false
# }
```

### Towncrier (Python)
```bash
pip3 install towncrier

# Configuration in pyproject.toml
cat >> pyproject.toml << 'TOWNCRIER'

[tool.towncrier]
package = "mypackage"
directory = "changes"
filename = "CHANGELOG.md"
title_format = "## [{version}] - {project_date}"

[[tool.towncrier.type]]
directory = "feature"
name = "Features"
showcontent = true

[[tool.towncrier.type]]
directory = "bugfix"
name = "Bug Fixes"
showcontent = true

[[tool.towncrier.type]]
directory = "breaking"
name = "Breaking Changes"
showcontent = true
TOWNCRIER

# Create change fragments
mkdir -p changes
echo "Add user search functionality" > changes/123.feature
echo "Fix login redirect loop" > changes/456.bugfix

# Build changelog
towncrier build --version 1.2.0
towncrier build --version 1.2.0 --draft   # Preview
```

---

## Man Page Generation

```bash
# Using pandoc to convert Markdown to man page
cat > mycommand.1.md << 'MANMD'
% MYCOMMAND(1) Version 1.0 | My Command Manual

# NAME
mycommand - brief description of what it does

# SYNOPSIS
**mycommand** [*OPTIONS*] *COMMAND* [*ARGS*]

# DESCRIPTION
Detailed description of the command and its purpose.

# OPTIONS
**-h**, **--help**
: Show help message and exit.

**-v**, **--verbose**
: Enable verbose output.

**-c** *CONFIG*, **--config** *CONFIG*
: Path to configuration file (default: /etc/mycommand.conf).

# COMMANDS
**start**
: Start the service.

**stop**
: Stop the service.

# EXAMPLES
Start the service with verbose output:

    mycommand -v start

Use a custom config file:

    mycommand -c /path/to/config.yml start

# FILES
*/etc/mycommand.conf*
: Default configuration file.

*/var/log/mycommand.log*
: Log file location.

# EXIT STATUS
**0**
: Successful execution.

**1**
: General error.

**2**
: Invalid arguments.

# SEE ALSO
**systemctl**(1), **journalctl**(1)

# BUGS
Report bugs at https://github.com/org/project/issues
MANMD

# Convert to man page
pandoc mycommand.1.md -s -t man -o mycommand.1

# View man page
man ./mycommand.1

# Install man page
sudo install -m 644 mycommand.1 /usr/local/share/man/man1/
sudo mandb
```

---

## README Generation

### README Template
```bash
cat > README_TEMPLATE.md << 'README'
# Project Name

Brief description of what this project does.

## Features

- Feature one
- Feature two
- Feature three

## Prerequisites

- Node.js >= 18
- PostgreSQL >= 15
- Redis >= 7

## Installation

```bash
git clone https://github.com/org/project.git
cd project
npm install
cp .env.example .env
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | - |

## Usage

```bash
# Development
npm run dev

# Production
npm run build
npm start

# Run tests
npm test
```

## API Documentation

See [API docs](docs/api.md) for endpoint documentation.

## Project Structure

```
src/
  routes/       # HTTP route handlers
  services/     # Business logic
  models/       # Data models
  middleware/    # Express middleware
  utils/        # Utility functions
tests/
  unit/         # Unit tests
  integration/  # Integration tests
```

## Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

## License

[MIT](LICENSE)
README
```

---

## Documentation Build and Serve

```bash
# Python Sphinx
cd docs && make html && python3 -m http.server 8000 --directory build/html

# MkDocs
mkdocs serve                     # Live reload on port 8000

# JSDoc
npx jsdoc -c jsdoc.json && python3 -m http.server 8000 --directory docs/api

# TypeDoc
npx typedoc && python3 -m http.server 8000 --directory docs/api

# Rust
cargo doc --open

# Go
godoc -http=:6060

# Doxygen
doxygen Doxyfile && python3 -m http.server 8000 --directory docs/api/html

# Markdown preview
grip README.md                   # GitHub-flavored markdown
```

---

## Workflows

### Generate Documentation for Existing Project
1. Identify language and existing doc patterns
2. Install appropriate doc generator
3. Add/fix doc comments in source code
4. Generate API documentation
5. Create or update README
6. Build and verify docs render correctly
7. Set up doc generation in CI

### Documentation CI Pipeline
```yaml
# .github/workflows/docs.yml
name: Documentation

on:
  push:
    branches: [main]

jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install sphinx sphinx-rtd-theme
      - run: cd docs && make html
      - uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./docs/build/html
```

### Changelog Update Workflow
1. Use conventional commit messages in all commits
2. Before release: `conventional-changelog -p angular -i CHANGELOG.md -s`
3. Review generated changelog
4. Edit for clarity if needed
5. Tag the release: `git tag -a v1.2.0 -m "Release 1.2.0"`
6. Push with tags: `git push --follow-tags`
