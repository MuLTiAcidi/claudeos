# Test Writer Agent

> Auto-generate unit, integration, and end-to-end tests with real testing frameworks and coverage tools.

## Safety Rules

- NEVER generate tests that modify production data or systems
- NEVER hardcode real credentials, API keys, or PII in test fixtures
- NEVER generate tests that depend on external network services without mocking
- NEVER skip or disable existing tests without explicit instruction
- Always use deterministic test data (avoid random values without seeds)
- Always clean up test artifacts (temp files, test databases) after tests
- Always ensure tests are isolated and can run independently

---

## Test Framework Installation

### Python
```bash
pip3 install pytest pytest-cov pytest-asyncio pytest-mock pytest-xdist pytest-timeout hypothesis factory-boy faker responses
```

### JavaScript/TypeScript
```bash
npm install --save-dev jest @types/jest ts-jest supertest @testing-library/react @testing-library/jest-dom msw nock faker
# Or Vitest
npm install --save-dev vitest @testing-library/react @testing-library/jest-dom happy-dom msw
```

### Go
```bash
go install gotest.tools/gotestsum@latest
go install github.com/stretchr/testify@latest
go install go.uber.org/mock/mockgen@latest
go install github.com/vektra/mockery/v2@latest
```

### Rust
```bash
cargo add --dev mockall rstest proptest wiremock tokio-test
```

---

## Python Testing (pytest)

### pytest Configuration
```toml
# pyproject.toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_functions = ["test_*"]
python_classes = ["Test*"]
addopts = [
    "-v",
    "--strict-markers",
    "--tb=short",
    "--cov=src",
    "--cov-report=term-missing",
    "--cov-report=html:htmlcov",
    "--cov-fail-under=80",
]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks integration tests",
    "e2e: marks end-to-end tests",
]
asyncio_mode = "auto"
```

### Unit Test Template
```python
# tests/test_user_service.py
import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone

from app.services.user_service import UserService
from app.models.user import User


class TestUserService:
    """Tests for UserService."""

    @pytest.fixture
    def mock_repo(self):
        """Create a mock repository."""
        repo = Mock()
        repo.get_by_id = Mock(return_value=User(
            id="uuid-123",
            email="test@example.com",
            name="Test User",
            created_at=datetime.now(timezone.utc),
        ))
        repo.create = Mock(return_value=User(
            id="uuid-456",
            email="new@example.com",
            name="New User",
            created_at=datetime.now(timezone.utc),
        ))
        return repo

    @pytest.fixture
    def service(self, mock_repo):
        """Create UserService with mocked dependencies."""
        return UserService(repository=mock_repo)

    def test_get_user_by_id(self, service, mock_repo):
        """Should return user when found."""
        result = service.get_user("uuid-123")

        assert result is not None
        assert result.id == "uuid-123"
        assert result.email == "test@example.com"
        mock_repo.get_by_id.assert_called_once_with("uuid-123")

    def test_get_user_not_found(self, service, mock_repo):
        """Should return None when user not found."""
        mock_repo.get_by_id.return_value = None

        result = service.get_user("nonexistent")

        assert result is None

    def test_create_user_success(self, service, mock_repo):
        """Should create user with valid data."""
        result = service.create_user(
            email="new@example.com",
            name="New User",
            password="secure123",
        )

        assert result.email == "new@example.com"
        mock_repo.create.assert_called_once()

    def test_create_user_duplicate_email(self, service, mock_repo):
        """Should raise error for duplicate email."""
        mock_repo.get_by_email = Mock(return_value=User(
            id="existing",
            email="dup@example.com",
            name="Existing",
            created_at=datetime.now(timezone.utc),
        ))

        with pytest.raises(ValueError, match="already exists"):
            service.create_user(
                email="dup@example.com",
                name="Dup User",
                password="secure123",
            )

    @pytest.mark.parametrize("email,expected_valid", [
        ("user@example.com", True),
        ("user@sub.example.com", True),
        ("invalid", False),
        ("@example.com", False),
        ("", False),
    ])
    def test_email_validation(self, service, email, expected_valid):
        """Should validate email format correctly."""
        assert service.is_valid_email(email) == expected_valid
```

### Async Test Template
```python
# tests/test_async_service.py
import pytest
from unittest.mock import AsyncMock

from app.services.async_service import AsyncDataService


class TestAsyncDataService:

    @pytest.fixture
    def mock_client(self):
        client = AsyncMock()
        client.fetch.return_value = {"data": "test"}
        return client

    @pytest.fixture
    def service(self, mock_client):
        return AsyncDataService(client=mock_client)

    @pytest.mark.asyncio
    async def test_fetch_data(self, service, mock_client):
        result = await service.fetch_data("resource-id")

        assert result == {"data": "test"}
        mock_client.fetch.assert_awaited_once_with("resource-id")

    @pytest.mark.asyncio
    async def test_fetch_data_retry_on_failure(self, service, mock_client):
        mock_client.fetch.side_effect = [ConnectionError("timeout"), {"data": "retry"}]

        result = await service.fetch_data("resource-id")

        assert result == {"data": "retry"}
        assert mock_client.fetch.await_count == 2
```

### Fixtures and Factories
```python
# tests/conftest.py
import pytest
from datetime import datetime, timezone
from unittest.mock import Mock

@pytest.fixture
def sample_user():
    """Provide a sample user dict."""
    return {
        "id": "uuid-123",
        "email": "test@example.com",
        "name": "Test User",
        "role": "user",
        "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc).isoformat(),
    }

@pytest.fixture
def db_session():
    """Provide a test database session."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.models.base import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    yield session

    session.rollback()
    session.close()

@pytest.fixture
def mock_redis():
    """Provide a mock Redis client."""
    redis = Mock()
    redis.get.return_value = None
    redis.set.return_value = True
    redis.delete.return_value = 1
    return redis
```

```python
# tests/factories.py
import factory
from datetime import datetime, timezone

class UserFactory(factory.Factory):
    class Meta:
        model = dict

    id = factory.Sequence(lambda n: f"uuid-{n:04d}")
    email = factory.LazyAttribute(lambda o: f"user{o.id.split('-')[1]}@example.com")
    name = factory.Faker("name")
    role = "user"
    is_active = True
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc).isoformat())
```

### FastAPI Integration Test
```python
# tests/test_api.py
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

class TestUsersAPI:

    @pytest.mark.asyncio
    async def test_health_check(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_create_user(self, client):
        response = await client.post("/api/v1/users", json={
            "email": "new@example.com",
            "name": "New User",
            "password": "secure123",
        })
        assert response.status_code == 201
        data = response.json()
        assert data["data"]["email"] == "new@example.com"

    @pytest.mark.asyncio
    async def test_create_user_invalid_email(self, client):
        response = await client.post("/api/v1/users", json={
            "email": "not-an-email",
            "name": "User",
            "password": "secure123",
        })
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_list_users_pagination(self, client):
        response = await client.get("/api/v1/users?page=1&limit=10")
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "pagination" in data
```

---

## JavaScript Testing (Jest)

### Jest Configuration
```javascript
// jest.config.js
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.{js,ts}'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
  },
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'clover'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  setupFilesAfterSetup: ['./tests/setup.js'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
};
```

### Unit Test Template
```javascript
// tests/unit/userService.test.js
const UserService = require('../../src/services/userService');

describe('UserService', () => {
  let userService;
  let mockRepository;

  beforeEach(() => {
    mockRepository = {
      findById: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      findByEmail: jest.fn(),
    };
    userService = new UserService(mockRepository);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('getUserById', () => {
    it('should return user when found', async () => {
      const mockUser = { id: '123', email: 'test@example.com', name: 'Test' };
      mockRepository.findById.mockResolvedValue(mockUser);

      const result = await userService.getUserById('123');

      expect(result).toEqual(mockUser);
      expect(mockRepository.findById).toHaveBeenCalledWith('123');
    });

    it('should return null when user not found', async () => {
      mockRepository.findById.mockResolvedValue(null);

      const result = await userService.getUserById('nonexistent');

      expect(result).toBeNull();
    });

    it('should throw on invalid id', async () => {
      await expect(userService.getUserById('')).rejects.toThrow('Invalid user ID');
    });
  });

  describe('createUser', () => {
    it('should create user with valid data', async () => {
      const userData = { email: 'new@example.com', name: 'New User', password: 'secure123' };
      const createdUser = { id: '456', ...userData };
      mockRepository.findByEmail.mockResolvedValue(null);
      mockRepository.create.mockResolvedValue(createdUser);

      const result = await userService.createUser(userData);

      expect(result.id).toBe('456');
      expect(mockRepository.create).toHaveBeenCalledTimes(1);
    });

    it('should reject duplicate email', async () => {
      mockRepository.findByEmail.mockResolvedValue({ id: 'existing' });

      await expect(
        userService.createUser({ email: 'dup@example.com', name: 'User', password: 'pass' })
      ).rejects.toThrow('already exists');
    });
  });

  describe('email validation', () => {
    it.each([
      ['user@example.com', true],
      ['user@sub.domain.com', true],
      ['invalid', false],
      ['@example.com', false],
      ['', false],
    ])('should validate %s as %s', (email, expected) => {
      expect(userService.isValidEmail(email)).toBe(expected);
    });
  });
});
```

### Express API Integration Test
```javascript
// tests/integration/users.test.js
const request = require('supertest');
const app = require('../../src/app');

describe('Users API', () => {
  describe('GET /health', () => {
    it('should return 200 with status ok', async () => {
      const res = await request(app).get('/health');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
    });
  });

  describe('POST /api/users', () => {
    it('should create a new user', async () => {
      const res = await request(app)
        .post('/api/users')
        .send({ email: 'new@example.com', name: 'New', password: 'secure123' })
        .expect('Content-Type', /json/);

      expect(res.status).toBe(201);
      expect(res.body.data.email).toBe('new@example.com');
    });

    it('should return 400 for invalid data', async () => {
      const res = await request(app)
        .post('/api/users')
        .send({ email: 'invalid' });

      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
    });
  });

  describe('GET /api/users', () => {
    it('should return paginated list', async () => {
      const res = await request(app)
        .get('/api/users?page=1&limit=10')
        .set('Authorization', `Bearer ${testToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.pagination).toBeDefined();
    });

    it('should return 401 without auth', async () => {
      const res = await request(app).get('/api/users');
      expect(res.status).toBe(401);
    });
  });
});
```

### Mock HTTP Requests (MSW)
```javascript
// tests/mocks/handlers.js
const { rest } = require('msw');

const handlers = [
  rest.get('https://api.external.com/data', (req, res, ctx) => {
    return res(
      ctx.status(200),
      ctx.json({ items: [{ id: 1, name: 'Test' }] })
    );
  }),

  rest.post('https://api.external.com/data', (req, res, ctx) => {
    return res(ctx.status(201), ctx.json({ id: 2, ...req.body }));
  }),
];

module.exports = { handlers };

// tests/mocks/server.js
const { setupServer } = require('msw/node');
const { handlers } = require('./handlers');
const server = setupServer(...handlers);
module.exports = { server };

// tests/setup.js
const { server } = require('./mocks/server');
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
```

---

## Go Testing

### Unit Test Template
```go
// internal/services/user_service_test.go
package services

import (
    "context"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/require"
)

// MockUserRepository is a mock implementation
type MockUserRepository struct {
    mock.Mock
}

func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*User, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) Create(ctx context.Context, user *User) error {
    args := m.Called(ctx, user)
    return args.Error(0)
}

func TestUserService_GetUser(t *testing.T) {
    t.Run("returns user when found", func(t *testing.T) {
        repo := new(MockUserRepository)
        service := NewUserService(repo)

        expected := &User{ID: "123", Email: "test@example.com", Name: "Test"}
        repo.On("GetByID", mock.Anything, "123").Return(expected, nil)

        user, err := service.GetUser(context.Background(), "123")

        require.NoError(t, err)
        assert.Equal(t, "123", user.ID)
        assert.Equal(t, "test@example.com", user.Email)
        repo.AssertExpectations(t)
    })

    t.Run("returns error when not found", func(t *testing.T) {
        repo := new(MockUserRepository)
        service := NewUserService(repo)

        repo.On("GetByID", mock.Anything, "nonexistent").Return(nil, ErrNotFound)

        user, err := service.GetUser(context.Background(), "nonexistent")

        assert.Nil(t, user)
        assert.ErrorIs(t, err, ErrNotFound)
    })
}

// Table-driven tests
func TestEmailValidation(t *testing.T) {
    tests := []struct {
        name     string
        email    string
        expected bool
    }{
        {"valid email", "user@example.com", true},
        {"valid subdomain", "user@sub.example.com", true},
        {"no at sign", "invalid", false},
        {"no local part", "@example.com", false},
        {"empty string", "", false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := IsValidEmail(tt.email)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

### Go HTTP Handler Test
```go
// internal/handlers/user_handler_test.go
package handlers

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestHealthHandler(t *testing.T) {
    req := httptest.NewRequest(http.MethodGet, "/health", nil)
    w := httptest.NewRecorder()

    HealthHandler(w, req)

    resp := w.Result()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var body map[string]string
    err := json.NewDecoder(resp.Body).Decode(&body)
    require.NoError(t, err)
    assert.Equal(t, "ok", body["status"])
}

func TestCreateUserHandler(t *testing.T) {
    payload := map[string]string{
        "email": "new@example.com",
        "name":  "New User",
    }
    body, _ := json.Marshal(payload)

    req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    w := httptest.NewRecorder()

    handler := NewUserHandler(mockService)
    handler.Create(w, req)

    assert.Equal(t, http.StatusCreated, w.Result().StatusCode)
}
```

### Go Test Commands
```bash
# Run all tests
go test ./...

# Verbose with race detection
go test -v -race ./...

# Specific package
go test -v ./internal/services/...

# Specific test
go test -v -run TestUserService_GetUser ./internal/services/

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
go tool cover -func=coverage.out

# Benchmarks
go test -bench=. -benchmem ./...

# Short tests only
go test -short ./...

# With timeout
go test -timeout 30s ./...

# Use gotestsum for better output
gotestsum --format testname ./...
gotestsum --format dots ./...
```

---

## Test Coverage

### Python Coverage
```bash
# Run with coverage
pytest --cov=src --cov-report=term-missing --cov-report=html

# Coverage commands
coverage run -m pytest
coverage report --show-missing
coverage html
coverage xml     # For CI

# Fail if below threshold
pytest --cov=src --cov-fail-under=80
```

### JavaScript/TypeScript Coverage
```bash
# Jest coverage
npx jest --coverage
npx jest --coverage --coverageReporters="text" "lcov"

# Vitest coverage
npx vitest --coverage

# Istanbul/nyc (for non-Jest)
npx nyc npm test
npx nyc report --reporter=text --reporter=lcov
```

### Go Coverage
```bash
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out          # Summary
go tool cover -html=coverage.out          # Browser
```

---

## Test Data Generation

### Faker Libraries
```python
# Python
from faker import Faker
fake = Faker()

user = {
    "name": fake.name(),
    "email": fake.email(),
    "address": fake.address(),
    "phone": fake.phone_number(),
    "company": fake.company(),
    "created_at": fake.date_time_this_year().isoformat(),
}
```

```javascript
// JavaScript
const { faker } = require('@faker-js/faker');

const user = {
  name: faker.person.fullName(),
  email: faker.internet.email(),
  address: faker.location.streetAddress(),
  phone: faker.phone.number(),
  company: faker.company.name(),
  createdAt: faker.date.recent().toISOString(),
};
```

### Property-Based Testing
```python
# Python — Hypothesis
from hypothesis import given, strategies as st

@given(st.text(min_size=1, max_size=100))
def test_string_reverse_is_involution(s):
    assert s == s[::-1][::-1]

@given(st.lists(st.integers()))
def test_sort_is_idempotent(lst):
    sorted_once = sorted(lst)
    sorted_twice = sorted(sorted_once)
    assert sorted_once == sorted_twice

@given(st.emails())
def test_email_parsing(email):
    assert "@" in email
    local, domain = email.split("@")
    assert len(local) > 0
    assert len(domain) > 0
```

---

## Running Tests

```bash
# Python
pytest                                    # All tests
pytest tests/unit/                        # Unit tests only
pytest tests/integration/                 # Integration tests only
pytest -k "test_create"                   # Pattern match
pytest -m "not slow"                      # Exclude slow tests
pytest -x                                 # Stop on first failure
pytest --lf                               # Rerun last failed
pytest -n auto                            # Parallel (pytest-xdist)

# JavaScript
npx jest                                  # All tests
npx jest --testPathPattern=unit           # Unit tests
npx jest --watch                          # Watch mode
npx jest --bail                           # Stop on first failure
npx jest --verbose                        # Detailed output

# Go
go test ./...                             # All
go test -v -run TestCreate ./...          # Pattern match
go test -short ./...                      # Skip long tests
go test -count=1 ./...                    # No cache

# Rust
cargo test                                # All tests
cargo test test_name                      # Pattern match
cargo test -- --nocapture                 # Show stdout
cargo test -- --test-threads=1            # Sequential
```

---

## Workflows

### Generate Tests for Existing Code
1. Identify the module/file to test
2. Analyze function signatures, inputs, outputs, side effects
3. Create test file following project conventions
4. Write happy path tests first
5. Add edge case tests (null, empty, boundary values)
6. Add error case tests
7. Add parameterized tests for input variations
8. Mock external dependencies
9. Run tests and verify all pass
10. Check coverage and add tests for uncovered branches

### Test Suite Organization
```
tests/
  unit/              # Fast, isolated, mock all deps
  integration/       # Test with real deps (DB, cache)
  e2e/               # Full system tests
  fixtures/          # Shared test data
  factories/         # Test data factories
  mocks/             # Mock implementations
  conftest.py        # Shared fixtures (Python)
  setup.js           # Test setup (JavaScript)
```
