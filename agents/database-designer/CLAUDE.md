# Database Designer Agent

> Schema design, migrations, query optimization, and database management with real tools.

## Safety Rules

- NEVER run destructive DDL (DROP TABLE, TRUNCATE) on production without explicit confirmation
- NEVER store passwords in plaintext — always use hashing (bcrypt, argon2)
- NEVER expose database credentials in code or logs
- NEVER run migrations on production without testing on staging first
- Always create backups before running destructive migrations
- Always use transactions for multi-step schema changes
- Always add indexes for foreign keys and frequently queried columns

---

## Database Client Installation

```bash
# PostgreSQL client
sudo apt-get install -y postgresql-client

# MySQL client
sudo apt-get install -y mysql-client

# SQLite
sudo apt-get install -y sqlite3

# Redis CLI
sudo apt-get install -y redis-tools

# MongoDB client
sudo apt-get install -y mongosh

# Universal SQL client
pip3 install pgcli mycli litecli
```

---

## PostgreSQL Schema Design

### Create Database and User
```sql
-- Connect as superuser
sudo -u postgres psql

-- Create database
CREATE DATABASE myapp;

-- Create application user with limited privileges
CREATE USER myapp_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT CONNECT ON DATABASE myapp TO myapp_user;

-- Connect to the database
\c myapp

-- Create schema
CREATE SCHEMA IF NOT EXISTS app;
GRANT USAGE ON SCHEMA app TO myapp_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO myapp_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO myapp_user;
```

### Common Schema Patterns

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table with best practices
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    email_normalized VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'moderator')),
    avatar_url TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    email_verified_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT users_email_unique UNIQUE (email_normalized),
    CONSTRAINT users_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Indexes
CREATE INDEX idx_users_email ON users (email_normalized);
CREATE INDEX idx_users_role ON users (role) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at ON users (created_at);
CREATE INDEX idx_users_active ON users (is_active) WHERE deleted_at IS NULL;

-- Posts table with foreign key
CREATE TABLE posts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    author_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    excerpt TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    published_at TIMESTAMPTZ,
    view_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT posts_slug_unique UNIQUE (slug)
);

CREATE INDEX idx_posts_author ON posts (author_id);
CREATE INDEX idx_posts_status ON posts (status, published_at DESC);
CREATE INDEX idx_posts_slug ON posts (slug);
CREATE INDEX idx_posts_published ON posts (published_at DESC) WHERE status = 'published';

CREATE TRIGGER update_posts_updated_at
    BEFORE UPDATE ON posts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Tags (many-to-many)
CREATE TABLE tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL,
    slug VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE post_tags (
    post_id UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, tag_id)
);

CREATE INDEX idx_post_tags_tag ON post_tags (tag_id);

-- Comments (self-referencing for threads)
CREATE TABLE comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    author_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES comments(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    is_edited BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_comments_post ON comments (post_id, created_at);
CREATE INDEX idx_comments_author ON comments (author_id);
CREATE INDEX idx_comments_parent ON comments (parent_id);

-- Audit log table
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    record_id UUID NOT NULL,
    action VARCHAR(10) NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    old_data JSONB,
    new_data JSONB,
    changed_by UUID REFERENCES users(id),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_table_record ON audit_log (table_name, record_id);
CREATE INDEX idx_audit_changed_at ON audit_log (changed_at);
```

### Soft Delete Pattern
```sql
-- Add soft delete to any table
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ;

-- Create view that excludes deleted records
CREATE VIEW active_users AS
SELECT * FROM users WHERE deleted_at IS NULL;

-- Partial index for active records only
CREATE INDEX idx_users_active_email ON users (email_normalized) WHERE deleted_at IS NULL;
```

---

## Migration Tools

### Alembic (Python/SQLAlchemy)

```bash
# Install
pip3 install alembic sqlalchemy psycopg2-binary

# Initialize
alembic init migrations

# Configure alembic.ini
sed -i 's|sqlalchemy.url = .*|sqlalchemy.url = postgresql://user:pass@localhost/myapp|' alembic.ini
```

```bash
# Create migration
alembic revision --autogenerate -m "create users table"

# Run migrations
alembic upgrade head

# Rollback one step
alembic downgrade -1

# Show current version
alembic current

# Show history
alembic history --verbose

# Show pending migrations
alembic heads
```

#### Alembic Migration Template
```python
# migrations/versions/001_create_users.py
"""create users table

Revision ID: 001
Create Date: 2024-01-01 00:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('idx_users_email', 'users', ['email'], unique=True)

def downgrade() -> None:
    op.drop_index('idx_users_email')
    op.drop_table('users')
```

### Flyway (Java/SQL)

```bash
# Install Flyway
wget -qO- https://repo1.maven.org/maven2/org/flywaydb/flyway-commandline/10.4.1/flyway-commandline-10.4.1-linux-x64.tar.gz | tar xz
export PATH=$PATH:$(pwd)/flyway-10.4.1

# Configure
cat > flyway.conf << 'FLYWAY'
flyway.url=jdbc:postgresql://localhost:5432/myapp
flyway.user=myapp_user
flyway.password=password
flyway.locations=filesystem:./sql/migrations
flyway.baselineOnMigrate=true
FLYWAY

# Create migration directory
mkdir -p sql/migrations

# Naming convention: V{version}__{description}.sql
cat > sql/migrations/V1__create_users_table.sql << 'SQL'
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SQL

# Run migrations
flyway migrate
flyway info
flyway validate
flyway repair     # Fix failed migrations
```

### Knex.js (Node.js)

```bash
npm install knex pg

# Initialize
npx knex init

# Create migration
npx knex migrate:make create_users_table

# Run migrations
npx knex migrate:latest
npx knex migrate:rollback
npx knex migrate:status

# Create seed
npx knex seed:make seed_users
npx knex seed:run
```

#### Knex Migration Template
```javascript
// migrations/20240101000000_create_users.js
exports.up = function(knex) {
  return knex.schema.createTable('users', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.string('email', 255).notNullable().unique();
    table.string('name', 100).notNullable();
    table.string('password_hash', 255).notNullable();
    table.enu('role', ['user', 'admin', 'moderator']).defaultTo('user');
    table.boolean('is_active').defaultTo(true);
    table.timestamps(true, true); // created_at, updated_at
    table.timestamp('deleted_at').nullable();

    table.index(['email']);
    table.index(['role']);
  });
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists('users');
};
```

### golang-migrate

```bash
# Install
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Create migration
migrate create -ext sql -dir migrations -seq create_users_table

# Run migrations
migrate -path migrations -database "postgresql://user:pass@localhost/myapp?sslmode=disable" up

# Rollback
migrate -path migrations -database "postgresql://user:pass@localhost/myapp?sslmode=disable" down 1

# Force version (fix dirty state)
migrate -path migrations -database "..." force VERSION
```

---

## Query Analysis and Optimization

### EXPLAIN / EXPLAIN ANALYZE

```sql
-- Basic explain
EXPLAIN SELECT * FROM users WHERE email = 'test@example.com';

-- With actual execution stats
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) SELECT * FROM users WHERE email = 'test@example.com';

-- JSON format (for tools)
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM users WHERE email = 'test@example.com';

-- Verbose (show all columns)
EXPLAIN (ANALYZE, VERBOSE, BUFFERS) SELECT * FROM users WHERE email = 'test@example.com';
```

### Common Query Optimization Patterns

```sql
-- Check for missing indexes (slow queries)
SELECT
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch
FROM pg_stat_user_tables
WHERE seq_scan > 100
ORDER BY seq_tup_read DESC
LIMIT 20;

-- Find unused indexes
SELECT
    schemaname || '.' || tablename AS table,
    indexname,
    idx_scan AS times_used,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE idx_scan = 0
AND indexrelname NOT LIKE '%_pkey'
ORDER BY pg_relation_size(indexrelid) DESC;

-- Find duplicate indexes
SELECT
    a.indrelid::regclass AS table,
    a.indexrelid::regclass AS index1,
    b.indexrelid::regclass AS index2
FROM pg_index a
JOIN pg_index b ON a.indrelid = b.indrelid
    AND a.indexrelid != b.indexrelid
    AND a.indkey::text = b.indkey::text
WHERE a.indexrelid > b.indexrelid;

-- Table sizes
SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS total_size,
    pg_size_pretty(pg_relation_size(schemaname || '.' || tablename)) AS table_size,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename) - pg_relation_size(schemaname || '.' || tablename)) AS index_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC;

-- Slow query log (PostgreSQL)
-- In postgresql.conf:
-- log_min_duration_statement = 500   # Log queries > 500ms
-- shared_preload_libraries = 'pg_stat_statements'

-- Using pg_stat_statements
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

SELECT
    calls,
    round(total_exec_time::numeric, 2) AS total_ms,
    round(mean_exec_time::numeric, 2) AS avg_ms,
    round(max_exec_time::numeric, 2) AS max_ms,
    rows,
    query
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 20;

-- Cache hit ratio (should be > 99%)
SELECT
    sum(heap_blks_read) AS heap_read,
    sum(heap_blks_hit) AS heap_hit,
    round(sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read))::numeric * 100, 2) AS cache_hit_ratio
FROM pg_statio_user_tables;
```

### Index Optimization

```sql
-- B-tree index (default, most common)
CREATE INDEX idx_users_email ON users (email);

-- Partial index (only index relevant rows)
CREATE INDEX idx_active_users ON users (email) WHERE is_active = true AND deleted_at IS NULL;

-- Composite index (column order matters!)
CREATE INDEX idx_posts_author_status ON posts (author_id, status, published_at DESC);

-- Covering index (include non-indexed columns)
CREATE INDEX idx_posts_list ON posts (status, published_at DESC) INCLUDE (title, excerpt);

-- GIN index for full-text search
ALTER TABLE posts ADD COLUMN search_vector tsvector;
CREATE INDEX idx_posts_search ON posts USING GIN (search_vector);

-- GIN index for JSONB
CREATE INDEX idx_users_metadata ON users USING GIN (metadata);

-- BRIN index for time-series data (very compact)
CREATE INDEX idx_events_created ON events USING BRIN (created_at);

-- Unique index
CREATE UNIQUE INDEX idx_users_email_unique ON users (LOWER(email));

-- Concurrent index creation (no table lock)
CREATE INDEX CONCURRENTLY idx_users_name ON users (name);

-- Reindex
REINDEX INDEX idx_users_email;
REINDEX TABLE users;
```

---

## MySQL-Specific Operations

```sql
-- Show table info
SHOW CREATE TABLE users;
DESCRIBE users;

-- Show indexes
SHOW INDEX FROM users;

-- Query analysis
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'test@example.com';

-- Slow query log
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow.log';

-- Table sizes
SELECT
    table_name,
    ROUND(data_length / 1024 / 1024, 2) AS data_mb,
    ROUND(index_length / 1024 / 1024, 2) AS index_mb,
    ROUND((data_length + index_length) / 1024 / 1024, 2) AS total_mb,
    table_rows
FROM information_schema.tables
WHERE table_schema = 'myapp'
ORDER BY (data_length + index_length) DESC;
```

---

## Database Normalization Guide

### Normal Forms

```
1NF: Each column contains atomic values, no repeating groups
  BAD:  phone = "555-1234, 555-5678"
  GOOD: Separate phone_numbers table with one row per phone

2NF: 1NF + no partial dependencies (every non-key depends on whole key)
  BAD:  order_items(order_id, product_id, product_name, quantity)
  GOOD: Separate products table, order_items references product_id

3NF: 2NF + no transitive dependencies (non-key depends only on key)
  BAD:  employees(id, department_id, department_name)
  GOOD: Separate departments table, employees references department_id
```

### When to Denormalize
```
- Read-heavy workloads where JOINs are expensive
- Caching frequently computed aggregates
- Search/filter fields from related tables
- Always document why denormalization was chosen
- Use materialized views instead of table denormalization when possible:
  CREATE MATERIALIZED VIEW user_stats AS
  SELECT user_id, COUNT(*) AS post_count, MAX(created_at) AS last_post
  FROM posts GROUP BY user_id;
  REFRESH MATERIALIZED VIEW CONCURRENTLY user_stats;
```

---

## ERD Generation

```bash
# Install ERD generation tools
pip3 install eralchemy2

# Generate ERD from SQLAlchemy models
eralchemy2 -i "postgresql://user:pass@localhost/myapp" -o erd.png

# Using SchemaSpy
docker run -v $(pwd)/output:/output \
  --network host \
  schemaspy/schemaspy:latest \
  -t pgsql \
  -host localhost \
  -port 5432 \
  -db myapp \
  -u myapp_user \
  -p password \
  -o /output

# Using dbdiagram.io format (DBML)
cat > schema.dbml << 'DBML'
Table users {
  id uuid [pk, default: `gen_random_uuid()`]
  email varchar(255) [not null, unique]
  name varchar(100) [not null]
  role varchar(20) [not null, default: 'user']
  created_at timestamptz [not null, default: `now()`]
}

Table posts {
  id uuid [pk, default: `gen_random_uuid()`]
  author_id uuid [not null, ref: > users.id]
  title varchar(255) [not null]
  content text [not null]
  status varchar(20) [not null, default: 'draft']
  created_at timestamptz [not null, default: `now()`]
}

Table comments {
  id uuid [pk]
  post_id uuid [not null, ref: > posts.id]
  author_id uuid [not null, ref: > users.id]
  parent_id uuid [ref: > comments.id]
  content text [not null]
  created_at timestamptz [not null, default: `now()`]
}
DBML

# Convert DBML to SQL
npm install -g @dbml/cli
dbml2sql schema.dbml --postgres -o schema.sql
sql2dbml schema.sql --postgres -o schema.dbml
```

---

## Backup and Restore

```bash
# PostgreSQL backup
pg_dump -Fc -h localhost -U myapp_user myapp > backup_$(date +%Y%m%d_%H%M%S).dump
pg_dump -Fp -h localhost -U myapp_user myapp > backup.sql       # Plain SQL

# PostgreSQL restore
pg_restore -h localhost -U myapp_user -d myapp backup.dump
psql -h localhost -U myapp_user -d myapp < backup.sql           # Plain SQL

# MySQL backup
mysqldump -h localhost -u root -p myapp > backup.sql
mysqldump -h localhost -u root -p --all-databases > all_backup.sql

# MySQL restore
mysql -h localhost -u root -p myapp < backup.sql

# SQLite backup
sqlite3 myapp.db ".backup backup.db"
```

---

## Connection Pooling

### PgBouncer Configuration
```ini
# /etc/pgbouncer/pgbouncer.ini
[databases]
myapp = host=localhost port=5432 dbname=myapp

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25
min_pool_size = 5
reserve_pool_size = 5
```

```bash
# Start PgBouncer
sudo systemctl start pgbouncer

# Check pool status
psql -h localhost -p 6432 -U pgbouncer pgbouncer -c "SHOW POOLS;"
psql -h localhost -p 6432 -U pgbouncer pgbouncer -c "SHOW STATS;"
```

---

## Workflows

### New Database Design Workflow
1. Define entities and their relationships
2. Create initial schema SQL with proper types and constraints
3. Add indexes for foreign keys and query patterns
4. Set up migration tool (Alembic/Flyway/Knex/golang-migrate)
5. Write initial migration
6. Create seed data for development
7. Generate ERD documentation
8. Set up backup schedule
9. Configure connection pooling for production

### Query Optimization Workflow
1. Identify slow queries: check slow query log or `pg_stat_statements`
2. Run `EXPLAIN (ANALYZE, BUFFERS)` on the query
3. Check for sequential scans on large tables
4. Add missing indexes
5. Consider partial/covering indexes
6. Rewrite query if needed (avoid SELECT *, use CTEs wisely)
7. Re-run EXPLAIN to verify improvement
8. Monitor cache hit ratio and table statistics

### Migration Safety Workflow
1. Write migration in development
2. Test migration on staging (with production-like data)
3. Create production backup: `pg_dump -Fc ...`
4. Run migration during low-traffic window
5. Monitor for errors
6. Verify application functionality
7. Keep rollback migration ready
