#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$script_dir"

db_name="${DB_NAME:-marketplace}"
db_host="${PGHOST:-${DB_HOST:-localhost}}"
db_port="${PGPORT:-${DB_PORT:-5432}}"
db_superuser="${PGSUPERUSER:-${DB_SUPERUSER:-postgres}}"
db_superpassword="${PGSUPERPASSWORD:-${DB_SUPERPASSWORD:-${PGPASSWORD:-}}}"

export PGHOST="$db_host"
export PGPORT="$db_port"
export PGUSER="$db_superuser"

if [ -n "$db_superpassword" ]; then
  export PGPASSWORD="$db_superpassword"
fi

sql_files=(
  "01_schema.sql"
  "05_constraints.sql"
  "06_seed.sql"
  "07_canary.sql"
  "02_grants.sql"
  "03_rls.sql"
  "04_masking.sql"
)

echo "Bootstrapping PostgreSQL database '${db_name}' on ${db_host}:${db_port}"

dropdb --if-exists -h "$db_host" -p "$db_port" -U "$db_superuser" "$db_name"
createdb -h "$db_host" -p "$db_port" -U "$db_superuser" "$db_name"

for file_name in "${sql_files[@]}"; do
  echo "Applying db/${file_name}"
  psql -h "$db_host" -p "$db_port" -U "$db_superuser" -d "$db_name" -v ON_ERROR_STOP=1 -f "$repo_root/db/$file_name" >/dev/null
done

echo "Enabling statement logging"
psql -h "$db_host" -p "$db_port" -U "$db_superuser" -d postgres -v ON_ERROR_STOP=1 <<'SQL'
ALTER SYSTEM SET log_statement = 'all';
SELECT pg_reload_conf();
SQL

echo "Verifying database posture"
psql -h "$db_host" -p "$db_port" -U "$db_superuser" -d "$db_name" -v ON_ERROR_STOP=1 <<'SQL'
SELECT current_setting('log_statement') AS log_statement;

SELECT rolname, rolcanlogin, rolsuper, rolbypassrls
  FROM pg_roles
 WHERE rolname IN ('role_app', 'role_customer', 'role_merchant', 'role_admin')
 ORDER BY rolname;

SELECT relname, relrowsecurity, relforcerowsecurity
  FROM pg_class
 WHERE relname IN (
    'platform_users', 'merchants', 'customers', 'products',
    'orders', 'order_items', 'payments', 'audit_log'
 )
 ORDER BY relname;

SELECT has_column_privilege('role_customer', 'payments', 'card_token', 'SELECT') AS customer_can_select_card_token;
SELECT has_column_privilege('role_customer', 'products', 'internal_cost', 'SELECT') AS customer_can_select_internal_cost;
SQL

echo "Database bootstrap complete."