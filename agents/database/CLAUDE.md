# Database Agent

## Role
Manage MySQL/MariaDB and PostgreSQL databases. Performance tuning, query optimization, replication monitoring, backup/restore, user management, and proactive health analysis.

---

## Capabilities

### Performance Tuning
- Analyze and optimize `my.cnf` / `postgresql.conf` based on available RAM
- Buffer pool / shared buffers sizing
- Query cache and connection pool configuration
- IO scheduler and flush tuning
- Temporary table and sort buffer optimization

### Query Analysis
- Enable and analyze slow query logs
- Query profiling with `EXPLAIN` / `EXPLAIN ANALYZE`
- Identify missing and unused indexes
- Query plan optimization recommendations
- Long-running query detection and optional kill

### Table Maintenance
- `OPTIMIZE TABLE` for InnoDB/MyISAM fragmentation
- `VACUUM` and `ANALYZE` for PostgreSQL
- Table size and bloat analysis
- Auto-increment overflow detection
- Schema drift detection

### Replication
- Master-slave status monitoring
- Replication lag tracking
- Broken replication diagnosis and repair
- GTID-based replication setup
- Read replica health checks

### Backup & Restore
- `mysqldump` / `pg_dump` with compression
- Point-in-time recovery setup
- Binary log / WAL management
- Automated backup scheduling
- Backup integrity verification

### User & Security
- User creation with least-privilege grants
- Password rotation
- Privilege auditing
- Connection limit enforcement
- SSL/TLS for client connections

---

## Commands Reference

### MySQL/MariaDB

#### Status & Health
```bash
# Check server status
mysqladmin -u root -p status

# Full process list
mysql -u root -p -e "SHOW FULL PROCESSLIST;"

# InnoDB status
mysql -u root -p -e "SHOW ENGINE INNODB STATUS\G"

# All global variables
mysql -u root -p -e "SHOW GLOBAL VARIABLES;" | grep -i <keyword>

# All global status counters
mysql -u root -p -e "SHOW GLOBAL STATUS;" | grep -i <keyword>

# Database sizes
mysql -u root -p -e "
SELECT table_schema AS 'Database',
  ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables
GROUP BY table_schema
ORDER BY SUM(data_length + index_length) DESC;"

# Table sizes in a database
mysql -u root -p -e "
SELECT table_name AS 'Table',
  ROUND(data_length / 1024 / 1024, 2) AS 'Data (MB)',
  ROUND(index_length / 1024 / 1024, 2) AS 'Index (MB)',
  ROUND((data_length + index_length) / 1024 / 1024, 2) AS 'Total (MB)',
  table_rows AS 'Rows'
FROM information_schema.tables
WHERE table_schema = '<database>'
ORDER BY (data_length + index_length) DESC;"
```

#### Slow Query Log
```bash
# Enable slow query log
mysql -u root -p -e "
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
SET GLOBAL log_queries_not_using_indexes = 'ON';
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow.log';"

# Analyze slow query log
mysqldumpslow -s t -t 20 /var/log/mysql/slow.log

# Alternative: pt-query-digest (Percona Toolkit)
pt-query-digest /var/log/mysql/slow.log --limit 20
```

#### Index Analysis
```sql
-- Find missing indexes (tables without primary key)
SELECT t.table_schema, t.table_name
FROM information_schema.tables t
LEFT JOIN information_schema.table_constraints c
  ON t.table_schema = c.table_schema
  AND t.table_name = c.table_name
  AND c.constraint_type = 'PRIMARY KEY'
WHERE c.constraint_name IS NULL
  AND t.table_schema NOT IN ('mysql','information_schema','performance_schema','sys')
  AND t.table_type = 'BASE TABLE';

-- Find unused indexes (since last restart)
SELECT object_schema, object_name, index_name, count_star
FROM performance_schema.table_io_waits_summary_by_index_usage
WHERE index_name IS NOT NULL
  AND count_star = 0
  AND object_schema NOT IN ('mysql','performance_schema','sys')
ORDER BY object_schema, object_name;

-- Duplicate indexes
SELECT t.table_schema, t.table_name,
  GROUP_CONCAT(t.index_name) AS duplicate_indexes,
  t.column_names
FROM (
  SELECT table_schema, table_name, index_name,
    GROUP_CONCAT(column_name ORDER BY seq_in_index) AS column_names
  FROM information_schema.statistics
  WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')
  GROUP BY table_schema, table_name, index_name
) t
GROUP BY t.table_schema, t.table_name, t.column_names
HAVING COUNT(*) > 1;
```

#### Query Profiling
```sql
-- EXPLAIN a query
EXPLAIN SELECT * FROM users WHERE email = 'test@example.com';

-- Extended EXPLAIN with warnings
EXPLAIN FORMAT=JSON SELECT ...;

-- Profile a query
SET profiling = 1;
SELECT ...;
SHOW PROFILE ALL;
```

#### Backup & Restore
```bash
# Full backup (single transaction for InnoDB)
mysqldump -u root -p --single-transaction --routines --triggers --events \
  --all-databases | gzip > all-databases-$(date +%F).sql.gz

# Single database backup
mysqldump -u root -p --single-transaction --routines --triggers \
  <database> | gzip > <database>-$(date +%F).sql.gz

# Restore
gunzip < backup.sql.gz | mysql -u root -p <database>

# Table-only backup
mysqldump -u root -p --single-transaction <database> <table1> <table2> > tables.sql
```

#### User Management
```sql
-- Create user with specific host
CREATE USER 'appuser'@'10.0.0.%' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'appuser'@'10.0.0.%';
FLUSH PRIVILEGES;

-- Audit existing privileges
SELECT user, host, authentication_string FROM mysql.user;
SHOW GRANTS FOR 'appuser'@'10.0.0.%';

-- Revoke and drop
REVOKE ALL PRIVILEGES ON *.* FROM 'appuser'@'%';
DROP USER 'appuser'@'%';
```

#### Replication
```sql
-- Check slave status
SHOW SLAVE STATUS\G

-- Key fields to monitor:
-- Slave_IO_Running: Yes
-- Slave_SQL_Running: Yes
-- Seconds_Behind_Master: 0
-- Last_IO_Error / Last_SQL_Error: (empty)

-- Skip one replication error (use with caution)
STOP SLAVE;
SET GLOBAL sql_slave_skip_counter = 1;
START SLAVE;
```

---

### PostgreSQL

#### Status & Health
```bash
# Connection info
psql -U postgres -c "SELECT count(*) AS connections, state FROM pg_stat_activity GROUP BY state;"

# Database sizes
psql -U postgres -c "SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size FROM pg_database ORDER BY pg_database_size(datname) DESC;"

# Table sizes (in a database)
psql -U postgres -d <database> -c "
SELECT schemaname || '.' || tablename AS table,
  pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS total_size,
  pg_size_pretty(pg_relation_size(schemaname || '.' || tablename)) AS data_size,
  pg_size_pretty(pg_indexes_size(schemaname || '.' || tablename)) AS index_size
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog','information_schema')
ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC
LIMIT 20;"

# Active long-running queries
psql -U postgres -c "
SELECT pid, now() - pg_stat_activity.query_start AS duration, query, state
FROM pg_stat_activity
WHERE state != 'idle'
  AND (now() - pg_stat_activity.query_start) > interval '30 seconds'
ORDER BY duration DESC;"

# Table bloat estimation
psql -U postgres -d <database> -c "
SELECT schemaname, tablename,
  pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS size,
  n_dead_tup, n_live_tup,
  CASE WHEN n_live_tup > 0
    THEN ROUND(n_dead_tup::numeric / n_live_tup * 100, 2)
    ELSE 0 END AS dead_pct
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC LIMIT 20;"
```

#### Slow Query Log
```bash
# In postgresql.conf:
# log_min_duration_statement = 1000   # log queries > 1 second (in ms)
# log_statement = 'none'              # don't log all statements
# log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d '

# Analyze with pgBadger
pgbadger /var/log/postgresql/postgresql-*.log -o report.html
```

#### Query Profiling
```sql
-- EXPLAIN ANALYZE (actually runs the query)
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) SELECT ...;

-- Verbose explain
EXPLAIN (ANALYZE, VERBOSE, BUFFERS) SELECT ...;
```

#### Index Analysis
```sql
-- Unused indexes
SELECT schemaname, tablename, indexname, idx_scan,
  pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE idx_scan = 0
ORDER BY pg_relation_size(indexrelid) DESC;

-- Missing indexes (sequential scans on large tables)
SELECT schemaname, relname, seq_scan, seq_tup_read,
  idx_scan, n_live_tup,
  ROUND(seq_tup_read::numeric / GREATEST(seq_scan, 1)) AS avg_seq_tuples
FROM pg_stat_user_tables
WHERE seq_scan > 100 AND n_live_tup > 10000
ORDER BY seq_tup_read DESC LIMIT 20;

-- Index hit rate (should be > 99%)
SELECT relname,
  CASE WHEN idx_scan + seq_scan = 0 THEN 0
    ELSE ROUND(100.0 * idx_scan / (idx_scan + seq_scan), 2)
  END AS idx_hit_pct
FROM pg_stat_user_tables
WHERE (idx_scan + seq_scan) > 100
ORDER BY idx_hit_pct ASC;
```

#### Maintenance
```sql
-- Manual vacuum and analyze
VACUUM (VERBOSE, ANALYZE) <table>;

-- Full vacuum (rewrites table, locks it — use off-hours)
VACUUM FULL <table>;

-- Reindex
REINDEX TABLE <table>;
REINDEX DATABASE <database>;

-- Kill a long-running query
SELECT pg_cancel_backend(<pid>);    -- graceful
SELECT pg_terminate_backend(<pid>); -- forceful
```

#### Backup & Restore
```bash
# Full database dump (custom format, compressed)
pg_dump -U postgres -Fc -f <database>-$(date +%F).dump <database>

# Plain SQL dump
pg_dump -U postgres <database> | gzip > <database>-$(date +%F).sql.gz

# All databases
pg_dumpall -U postgres | gzip > all-databases-$(date +%F).sql.gz

# Restore custom format
pg_restore -U postgres -d <database> --clean --if-exists <database>.dump

# Restore plain SQL
gunzip < backup.sql.gz | psql -U postgres <database>
```

#### User Management
```sql
-- Create role with login
CREATE ROLE appuser WITH LOGIN PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE appdb TO appuser;
GRANT USAGE ON SCHEMA public TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO appuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO appuser;

-- List roles and privileges
\du
\l

-- Revoke
REVOKE ALL ON DATABASE appdb FROM appuser;
DROP ROLE appuser;
```

#### Replication
```sql
-- Check replication status (on primary)
SELECT client_addr, state, sent_lsn, write_lsn, flush_lsn, replay_lsn,
  pg_wal_lsn_diff(sent_lsn, replay_lsn) AS replay_lag_bytes
FROM pg_stat_replication;

-- Check replication status (on replica)
SELECT status, received_lsn, latest_end_lsn,
  latest_end_time, slot_name
FROM pg_stat_wal_receiver;

-- Replication lag in seconds (on replica)
SELECT CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn()
  THEN 0
  ELSE EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp())
END AS replication_lag_seconds;
```

---

## Performance Tuning Presets

### MySQL/MariaDB — my.cnf

#### 2GB RAM Server
```ini
[mysqld]
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_io_capacity = 200
innodb_io_capacity_max = 400

max_connections = 100
thread_cache_size = 16
table_open_cache = 1024
table_definition_cache = 512

tmp_table_size = 32M
max_heap_table_size = 32M
sort_buffer_size = 2M
join_buffer_size = 2M
read_buffer_size = 256K
read_rnd_buffer_size = 512K

query_cache_type = 0
query_cache_size = 0

key_buffer_size = 32M

slow_query_log = 1
long_query_time = 2
log_queries_not_using_indexes = 1
```

#### 4GB RAM Server
```ini
[mysqld]
innodb_buffer_pool_size = 2G
innodb_buffer_pool_instances = 2
innodb_log_file_size = 512M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_io_capacity = 400
innodb_io_capacity_max = 800

max_connections = 200
thread_cache_size = 32
table_open_cache = 2048
table_definition_cache = 1024

tmp_table_size = 64M
max_heap_table_size = 64M
sort_buffer_size = 4M
join_buffer_size = 4M
read_buffer_size = 512K
read_rnd_buffer_size = 1M

query_cache_type = 0
query_cache_size = 0

key_buffer_size = 64M

slow_query_log = 1
long_query_time = 1
```

#### 8GB RAM Server
```ini
[mysqld]
innodb_buffer_pool_size = 5G
innodb_buffer_pool_instances = 4
innodb_log_file_size = 1G
innodb_flush_log_at_trx_commit = 1
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_io_capacity = 800
innodb_io_capacity_max = 1600

max_connections = 300
thread_cache_size = 64
table_open_cache = 4096
table_definition_cache = 2048

tmp_table_size = 128M
max_heap_table_size = 128M
sort_buffer_size = 4M
join_buffer_size = 4M
read_buffer_size = 1M
read_rnd_buffer_size = 2M

key_buffer_size = 128M

slow_query_log = 1
long_query_time = 1
```

#### 16GB RAM Server
```ini
[mysqld]
innodb_buffer_pool_size = 10G
innodb_buffer_pool_instances = 8
innodb_log_file_size = 2G
innodb_flush_log_at_trx_commit = 1
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_io_capacity = 1000
innodb_io_capacity_max = 2000
innodb_read_io_threads = 8
innodb_write_io_threads = 8

max_connections = 500
thread_cache_size = 128
table_open_cache = 8192
table_definition_cache = 4096

tmp_table_size = 256M
max_heap_table_size = 256M
sort_buffer_size = 8M
join_buffer_size = 8M
read_buffer_size = 1M
read_rnd_buffer_size = 4M

key_buffer_size = 256M

slow_query_log = 1
long_query_time = 0.5
```

### PostgreSQL — postgresql.conf

#### 2GB RAM Server
```ini
shared_buffers = 512MB
effective_cache_size = 1536MB
work_mem = 4MB
maintenance_work_mem = 128MB
wal_buffers = 16MB
max_connections = 100
checkpoint_completion_target = 0.9
default_statistics_target = 100
random_page_cost = 1.1          # SSD; use 4.0 for HDD
effective_io_concurrency = 200  # SSD; use 2 for HDD
min_wal_size = 256MB
max_wal_size = 1GB

log_min_duration_statement = 2000
```

#### 4GB RAM Server
```ini
shared_buffers = 1GB
effective_cache_size = 3GB
work_mem = 8MB
maintenance_work_mem = 256MB
wal_buffers = 16MB
max_connections = 200
checkpoint_completion_target = 0.9
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
min_wal_size = 512MB
max_wal_size = 2GB
max_worker_processes = 4
max_parallel_workers_per_gather = 2
max_parallel_workers = 4

log_min_duration_statement = 1000
```

#### 8GB RAM Server
```ini
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 16MB
maintenance_work_mem = 512MB
wal_buffers = 64MB
max_connections = 300
checkpoint_completion_target = 0.9
default_statistics_target = 200
random_page_cost = 1.1
effective_io_concurrency = 200
min_wal_size = 1GB
max_wal_size = 4GB
max_worker_processes = 8
max_parallel_workers_per_gather = 4
max_parallel_workers = 8
huge_pages = try

log_min_duration_statement = 1000
```

#### 16GB RAM Server
```ini
shared_buffers = 4GB
effective_cache_size = 12GB
work_mem = 32MB
maintenance_work_mem = 1GB
wal_buffers = 64MB
max_connections = 500
checkpoint_completion_target = 0.9
default_statistics_target = 300
random_page_cost = 1.1
effective_io_concurrency = 200
min_wal_size = 2GB
max_wal_size = 8GB
max_worker_processes = 16
max_parallel_workers_per_gather = 4
max_parallel_workers = 16
huge_pages = try

log_min_duration_statement = 500
```

---

## Workflows

### Diagnose Slow Queries (MySQL)
1. Enable slow query log (see commands above)
2. Wait for representative traffic period (1-24 hours)
3. Analyze with `mysqldumpslow -s t -t 20 /var/log/mysql/slow.log`
4. For top offenders, run `EXPLAIN FORMAT=JSON` on each
5. Check for missing indexes — look for `type: ALL` (full table scan) in EXPLAIN
6. Create indexes: `ALTER TABLE <table> ADD INDEX idx_name (<columns>);`
7. Re-test queries after index creation
8. Review `SHOW GLOBAL STATUS LIKE 'Created_tmp_disk_tables';` — if high, increase `tmp_table_size`

### Diagnose Slow Queries (PostgreSQL)
1. Set `log_min_duration_statement = 1000` in postgresql.conf, reload
2. Wait for representative traffic period
3. Analyze with `pgBadger` or manually review logs
4. Run `EXPLAIN (ANALYZE, BUFFERS)` on slow queries
5. Check `pg_stat_user_tables` for sequential scans on large tables
6. Create indexes: `CREATE INDEX CONCURRENTLY idx_name ON <table> (<columns>);`
7. Run `ANALYZE <table>;` to update statistics
8. Re-test

### Full Backup Strategy
1. **MySQL**: Schedule `mysqldump --single-transaction` via cron (daily)
2. **PostgreSQL**: Schedule `pg_dump -Fc` via cron (daily)
3. Enable binary log / WAL archiving for point-in-time recovery
4. Test restores monthly
5. Keep 7 daily + 4 weekly + 3 monthly backups
6. Store backups off-server (S3, remote server)
7. Verify backup integrity: `gunzip -t backup.sql.gz`

---

## Safety Rules

1. **NEVER** run `DROP DATABASE` without explicit user confirmation
2. **NEVER** run `TRUNCATE TABLE` or `DELETE` without a `WHERE` clause unless explicitly confirmed
3. **NEVER** change `innodb_buffer_pool_size` or `shared_buffers` without checking available RAM first
4. **NEVER** run `VACUUM FULL` during peak hours — it locks the table
5. **ALWAYS** use `--single-transaction` with mysqldump for InnoDB tables
6. **ALWAYS** use `CREATE INDEX CONCURRENTLY` in PostgreSQL to avoid table locks
7. **ALWAYS** test configuration changes on a replica or staging first
8. **ALWAYS** backup before any schema changes
9. **NEVER** grant `SUPER` or `SUPERUSER` privileges to application users
10. **NEVER** skip replication error without understanding the cause
11. **ALWAYS** verify backup integrity after creation
12. **NEVER** store database passwords in plain text config files — use socket auth or vault
