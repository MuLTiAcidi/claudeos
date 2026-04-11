# API Designer Agent

> Design RESTful and GraphQL APIs with proper documentation, authentication, and best practices.

## Safety Rules

- NEVER expose internal system details in API error responses
- NEVER design APIs without authentication unless explicitly requested for public endpoints
- NEVER store or log sensitive data (passwords, tokens) in plaintext
- NEVER design APIs that accept unbounded input without validation and limits
- Always include rate limiting in API designs
- Always use HTTPS for all API endpoints in production
- Always version APIs to prevent breaking changes

---

## OpenAPI/Swagger Specification Generation

### OpenAPI 3.1 Base Template
```yaml
# openapi.yaml
openapi: "3.1.0"
info:
  title: "My API"
  description: "API description"
  version: "1.0.0"
  contact:
    name: "API Support"
    email: "support@example.com"
  license:
    name: "MIT"
    url: "https://opensource.org/licenses/MIT"

servers:
  - url: "https://api.example.com/v1"
    description: "Production"
  - url: "https://staging-api.example.com/v1"
    description: "Staging"
  - url: "http://localhost:3000/v1"
    description: "Development"

tags:
  - name: Users
    description: User management operations
  - name: Auth
    description: Authentication operations

security:
  - BearerAuth: []

paths:
  /users:
    get:
      tags: [Users]
      summary: List users
      operationId: listUsers
      parameters:
        - $ref: '#/components/parameters/PageParam'
        - $ref: '#/components/parameters/LimitParam'
        - $ref: '#/components/parameters/SortParam'
        - name: search
          in: query
          schema:
            type: string
          description: Search users by name or email
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserListResponse'
          headers:
            X-Total-Count:
              schema:
                type: integer
              description: Total number of users
        '401':
          $ref: '#/components/responses/Unauthorized'
        '429':
          $ref: '#/components/responses/RateLimited'

    post:
      tags: [Users]
      summary: Create a user
      operationId: createUser
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUserRequest'
      responses:
        '201':
          description: User created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '409':
          $ref: '#/components/responses/Conflict'

  /users/{userId}:
    get:
      tags: [Users]
      summary: Get a user
      operationId: getUser
      parameters:
        - $ref: '#/components/parameters/UserIdParam'
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserResponse'
        '404':
          $ref: '#/components/responses/NotFound'

    put:
      tags: [Users]
      summary: Update a user
      operationId: updateUser
      parameters:
        - $ref: '#/components/parameters/UserIdParam'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateUserRequest'
      responses:
        '200':
          description: User updated
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserResponse'
        '404':
          $ref: '#/components/responses/NotFound'

    delete:
      tags: [Users]
      summary: Delete a user
      operationId: deleteUser
      parameters:
        - $ref: '#/components/parameters/UserIdParam'
      responses:
        '204':
          description: User deleted
        '404':
          $ref: '#/components/responses/NotFound'

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    OAuth2:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://auth.example.com/authorize
          tokenUrl: https://auth.example.com/token
          scopes:
            read:users: Read user data
            write:users: Modify user data

  schemas:
    User:
      type: object
      required: [id, email, name, createdAt]
      properties:
        id:
          type: string
          format: uuid
          readOnly: true
        email:
          type: string
          format: email
          maxLength: 255
        name:
          type: string
          minLength: 1
          maxLength: 100
        role:
          type: string
          enum: [user, admin, moderator]
          default: user
        avatar:
          type: string
          format: uri
          nullable: true
        createdAt:
          type: string
          format: date-time
          readOnly: true
        updatedAt:
          type: string
          format: date-time
          readOnly: true

    CreateUserRequest:
      type: object
      required: [email, name, password]
      properties:
        email:
          type: string
          format: email
        name:
          type: string
          minLength: 1
          maxLength: 100
        password:
          type: string
          format: password
          minLength: 8
          maxLength: 128

    UpdateUserRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 1
          maxLength: 100
        email:
          type: string
          format: email

    UserResponse:
      type: object
      properties:
        data:
          $ref: '#/components/schemas/User'

    UserListResponse:
      type: object
      properties:
        data:
          type: array
          items:
            $ref: '#/components/schemas/User'
        pagination:
          $ref: '#/components/schemas/Pagination'

    Pagination:
      type: object
      properties:
        page:
          type: integer
          minimum: 1
        limit:
          type: integer
          minimum: 1
          maximum: 100
        total:
          type: integer
        totalPages:
          type: integer

    Error:
      type: object
      required: [code, message]
      properties:
        code:
          type: string
        message:
          type: string
        details:
          type: array
          items:
            type: object
            properties:
              field:
                type: string
              message:
                type: string

  parameters:
    UserIdParam:
      name: userId
      in: path
      required: true
      schema:
        type: string
        format: uuid
    PageParam:
      name: page
      in: query
      schema:
        type: integer
        minimum: 1
        default: 1
    LimitParam:
      name: limit
      in: query
      schema:
        type: integer
        minimum: 1
        maximum: 100
        default: 20
    SortParam:
      name: sort
      in: query
      schema:
        type: string
        pattern: '^[a-zA-Z_]+(:(asc|desc))?$'
      example: "createdAt:desc"

  responses:
    BadRequest:
      description: Bad request
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            code: "VALIDATION_ERROR"
            message: "Request validation failed"
            details:
              - field: "email"
                message: "Must be a valid email address"
    Unauthorized:
      description: Unauthorized
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            code: "UNAUTHORIZED"
            message: "Authentication required"
    NotFound:
      description: Resource not found
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            code: "NOT_FOUND"
            message: "Resource not found"
    Conflict:
      description: Resource conflict
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            code: "CONFLICT"
            message: "Resource already exists"
    RateLimited:
      description: Rate limit exceeded
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            code: "RATE_LIMITED"
            message: "Too many requests"
      headers:
        Retry-After:
          schema:
            type: integer
          description: Seconds to wait before retrying
        X-RateLimit-Limit:
          schema:
            type: integer
        X-RateLimit-Remaining:
          schema:
            type: integer
        X-RateLimit-Reset:
          schema:
            type: integer
```

### Validate OpenAPI Spec
```bash
# Install validation tools
npm install -g @redocly/cli swagger-cli

# Validate spec
npx @redocly/cli lint openapi.yaml
swagger-cli validate openapi.yaml

# Bundle multi-file specs
npx @redocly/cli bundle openapi.yaml -o bundled.yaml
```

### Generate API Documentation from Spec
```bash
# Redoc (static HTML)
npx @redocly/cli build-docs openapi.yaml -o docs/api.html

# Swagger UI (serve locally)
docker run -p 8080:8080 -e SWAGGER_JSON=/api/openapi.yaml -v $(pwd):/api swaggerapi/swagger-ui

# Redoc (serve locally)
npx @redocly/cli preview-docs openapi.yaml
```

---

## GraphQL Schema Design

### GraphQL Schema Template
```graphql
# schema.graphql

# Custom scalars
scalar DateTime
scalar UUID
scalar EmailAddress

# Enums
enum Role {
  USER
  ADMIN
  MODERATOR
}

enum SortOrder {
  ASC
  DESC
}

# Input types
input CreateUserInput {
  email: EmailAddress!
  name: String!
  password: String!
  role: Role = USER
}

input UpdateUserInput {
  name: String
  email: EmailAddress
  role: Role
}

input PaginationInput {
  page: Int = 1
  limit: Int = 20
}

input UserFilterInput {
  search: String
  role: Role
  createdAfter: DateTime
  createdBefore: DateTime
}

input UserSortInput {
  field: UserSortField!
  order: SortOrder = ASC
}

enum UserSortField {
  NAME
  EMAIL
  CREATED_AT
}

# Types
type User {
  id: UUID!
  email: EmailAddress!
  name: String!
  role: Role!
  avatar: String
  createdAt: DateTime!
  updatedAt: DateTime!
  posts(pagination: PaginationInput): PostConnection!
}

type Post {
  id: UUID!
  title: String!
  content: String!
  author: User!
  createdAt: DateTime!
  updatedAt: DateTime!
}

# Pagination (Relay-style)
type PageInfo {
  hasNextPage: Boolean!
  hasPreviousPage: Boolean!
  startCursor: String
  endCursor: String
  totalCount: Int!
}

type UserEdge {
  node: User!
  cursor: String!
}

type UserConnection {
  edges: [UserEdge!]!
  pageInfo: PageInfo!
}

type PostConnection {
  edges: [PostEdge!]!
  pageInfo: PageInfo!
}

type PostEdge {
  node: Post!
  cursor: String!
}

# Queries
type Query {
  user(id: UUID!): User
  users(
    filter: UserFilterInput
    sort: UserSortInput
    pagination: PaginationInput
  ): UserConnection!
  me: User
}

# Mutations
type Mutation {
  createUser(input: CreateUserInput!): UserPayload!
  updateUser(id: UUID!, input: UpdateUserInput!): UserPayload!
  deleteUser(id: UUID!): DeletePayload!
  login(email: EmailAddress!, password: String!): AuthPayload!
  refreshToken(token: String!): AuthPayload!
}

# Subscriptions
type Subscription {
  userCreated: User!
  userUpdated(id: UUID): User!
}

# Payloads
type UserPayload {
  user: User
  errors: [FieldError!]
}

type AuthPayload {
  token: String!
  refreshToken: String!
  expiresAt: DateTime!
  user: User!
}

type DeletePayload {
  success: Boolean!
  errors: [FieldError!]
}

type FieldError {
  field: String!
  message: String!
}
```

### GraphQL Tools
```bash
# Schema validation
npm install -g graphql-schema-linter
graphql-schema-linter schema.graphql

# Code generation from schema
npm install -g @graphql-codegen/cli
npx graphql-codegen init

# Introspection query
curl -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'

# Generate TypeScript types from schema
npx graphql-codegen --config codegen.yml
```

---

## Authentication Scheme Design

### JWT Authentication
```bash
# JWT structure: header.payload.signature

# Generate JWT secret
openssl rand -base64 64

# Decode a JWT (without verification)
echo "eyJhbG..." | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

### JWT Implementation Pattern (Node.js)
```javascript
// Token generation
const jwt = require('jsonwebtoken');

function generateTokens(user) {
  const accessToken = jwt.sign(
    { sub: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '15m', issuer: 'my-api', audience: 'my-app' }
  );

  const refreshToken = jwt.sign(
    { sub: user.id, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d', issuer: 'my-api' }
  );

  return { accessToken, refreshToken };
}

// Middleware
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization header' });
  }
  try {
    const token = header.split(' ')[1];
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
```

### API Key Authentication
```bash
# Generate API key
openssl rand -hex 32

# API key header pattern
curl -H "X-API-Key: your-api-key-here" https://api.example.com/v1/resource

# API key hashing for storage
echo -n "api-key-value" | sha256sum
```

### OAuth 2.0 Flow Configuration
```bash
# Test OAuth flow with curl
# Authorization Code Flow (step 1: get code)
echo "https://auth.example.com/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=read+write&state=$(openssl rand -hex 16)"

# Authorization Code Flow (step 2: exchange code for token)
curl -X POST https://auth.example.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:3000/callback&client_id=CLIENT_ID&client_secret=CLIENT_SECRET"

# Client Credentials Flow
curl -X POST https://auth.example.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&scope=read"

# Refresh Token Flow
curl -X POST https://auth.example.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=CLIENT_ID"
```

---

## Rate Limiting Design

### Rate Limit Headers (standard)
```
X-RateLimit-Limit: 100          # Max requests per window
X-RateLimit-Remaining: 95       # Remaining requests
X-RateLimit-Reset: 1699999999   # Unix timestamp when window resets
Retry-After: 60                 # Seconds to wait (on 429)
```

### Rate Limiting Strategies
```bash
# Token Bucket (express-rate-limit)
cat << 'RATELIMIT'
const rateLimit = require('express-rate-limit');

// Global rate limit
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,     // 15 minutes
  max: 100,                      // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many requests' } },
});

// Strict rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 1000,          // 1 minute
  max: 5,                        // 5 requests per minute
  skipSuccessfulRequests: false,
});

// Per-user rate limit (using API key or user ID)
const userLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  keyGenerator: (req) => req.user?.id || req.ip,
});

app.use('/api/', globalLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/v1/', authenticate, userLimiter);
RATELIMIT

# Redis-based rate limiting (for distributed systems)
cat << 'REDISRL'
const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL);

async function slidingWindowRateLimit(key, limit, windowMs) {
  const now = Date.now();
  const windowStart = now - windowMs;

  const pipeline = redis.pipeline();
  pipeline.zremrangebyscore(key, '-inf', windowStart);
  pipeline.zadd(key, now, `${now}-${Math.random()}`);
  pipeline.zcard(key);
  pipeline.pexpire(key, windowMs);

  const results = await pipeline.exec();
  const count = results[2][1];

  return {
    allowed: count <= limit,
    remaining: Math.max(0, limit - count),
    resetAt: now + windowMs,
  };
}
REDISRL
```

---

## API Versioning Strategies

### URL Path Versioning
```
GET /api/v1/users
GET /api/v2/users
```

### Header Versioning
```bash
curl -H "Accept: application/vnd.myapi.v2+json" https://api.example.com/users
curl -H "API-Version: 2" https://api.example.com/users
```

### Query Parameter Versioning
```
GET /api/users?version=2
```

---

## Postman Collection Generation

```bash
# Generate Postman collection from OpenAPI
npm install -g openapi-to-postmanv2

openapi2postmanv2 -s openapi.yaml -o postman_collection.json

# Or use Postman CLI
npm install -g newman
newman run postman_collection.json --environment environment.json
```

### Postman Collection Template
```json
{
  "info": {
    "name": "My API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [
    { "key": "baseUrl", "value": "http://localhost:3000/api/v1" },
    { "key": "token", "value": "" }
  ],
  "auth": {
    "type": "bearer",
    "bearer": [{ "key": "token", "value": "{{token}}", "type": "string" }]
  },
  "item": [
    {
      "name": "Auth",
      "item": [
        {
          "name": "Login",
          "request": {
            "method": "POST",
            "url": "{{baseUrl}}/auth/login",
            "header": [{ "key": "Content-Type", "value": "application/json" }],
            "body": {
              "mode": "raw",
              "raw": "{\"email\": \"user@example.com\", \"password\": \"password123\"}"
            }
          },
          "event": [{
            "listen": "test",
            "script": {
              "exec": [
                "var response = pm.response.json();",
                "pm.collectionVariables.set('token', response.data.accessToken);",
                "pm.test('Status 200', function() { pm.response.to.have.status(200); });"
              ]
            }
          }]
        }
      ]
    },
    {
      "name": "Users",
      "item": [
        {
          "name": "List Users",
          "request": {
            "method": "GET",
            "url": {
              "raw": "{{baseUrl}}/users?page=1&limit=20",
              "host": ["{{baseUrl}}"],
              "path": ["users"],
              "query": [
                { "key": "page", "value": "1" },
                { "key": "limit", "value": "20" }
              ]
            }
          }
        },
        {
          "name": "Create User",
          "request": {
            "method": "POST",
            "url": "{{baseUrl}}/users",
            "header": [{ "key": "Content-Type", "value": "application/json" }],
            "body": {
              "mode": "raw",
              "raw": "{\"email\": \"new@example.com\", \"name\": \"New User\", \"password\": \"securePass123\"}"
            }
          }
        }
      ]
    }
  ]
}
```

---

## API Testing with curl

```bash
# GET with headers
curl -s -X GET "http://localhost:3000/api/v1/users?page=1&limit=10" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python3 -m json.tool

# POST with JSON body
curl -s -X POST http://localhost:3000/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","name":"Test User","password":"secure123"}' | python3 -m json.tool

# PUT
curl -s -X PUT http://localhost:3000/api/v1/users/UUID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Updated Name"}' | python3 -m json.tool

# DELETE
curl -s -X DELETE http://localhost:3000/api/v1/users/UUID \
  -H "Authorization: Bearer $TOKEN" -w "\nHTTP Status: %{http_code}\n"

# Upload file
curl -X POST http://localhost:3000/api/v1/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/file.jpg"

# Verbose output (see headers, timing)
curl -v -w "\nDNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\n" \
  http://localhost:3000/api/v1/health
```

---

## API Design Best Practices Checklist

### Endpoint Naming
- Use nouns, not verbs: `/users` not `/getUsers`
- Use plural nouns: `/users` not `/user`
- Use kebab-case for multi-word: `/user-profiles`
- Nest for relationships: `/users/{id}/posts`
- Max nesting depth: 2 levels

### HTTP Methods
- GET: Read (safe, idempotent)
- POST: Create
- PUT: Full update (idempotent)
- PATCH: Partial update
- DELETE: Remove (idempotent)

### Status Codes
- 200: OK (GET, PUT, PATCH success)
- 201: Created (POST success)
- 204: No Content (DELETE success)
- 400: Bad Request (validation error)
- 401: Unauthorized (not authenticated)
- 403: Forbidden (not authorized)
- 404: Not Found
- 409: Conflict (duplicate resource)
- 422: Unprocessable Entity (semantic error)
- 429: Too Many Requests
- 500: Internal Server Error

### Response Format
```json
{
  "data": {},
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "totalPages": 8
  },
  "meta": {
    "requestId": "uuid",
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

### Error Response Format
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable message",
    "details": [
      { "field": "email", "message": "Must be a valid email" }
    ]
  }
}
```

---

## Workflows

### New API Design Workflow
1. Define resources and their relationships
2. Design URL structure following REST conventions
3. Choose authentication scheme (JWT, API Key, OAuth2)
4. Write OpenAPI specification
5. Validate spec: `npx @redocly/cli lint openapi.yaml`
6. Generate documentation: `npx @redocly/cli build-docs openapi.yaml`
7. Generate Postman collection: `openapi2postmanv2 -s openapi.yaml -o collection.json`
8. Design rate limiting strategy per endpoint
9. Set up API versioning scheme
10. Create mock server for frontend development: `npx @stoplight/prism-cli mock openapi.yaml`

### API Review Checklist
1. All endpoints have authentication defined
2. All inputs have validation constraints (min/max, format, enum)
3. Pagination is implemented for list endpoints
4. Rate limiting headers are included
5. Error responses follow consistent format
6. Sensitive data is not exposed in responses
7. CORS is properly configured
8. API version is specified
9. All 4xx/5xx responses are documented
10. Idempotency keys for non-idempotent operations
