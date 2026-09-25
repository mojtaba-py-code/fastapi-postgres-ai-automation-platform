#!/bin/sh
# First-boot provisioning (runs once, as the postgres superuser, on an empty
# data directory). Creates least-privilege roles:
#
#   nexusflow_migrator  schema owner, BYPASSRLS - used only by `nexusflow migrate`
#   nexusflow_app       NOBYPASSRLS - the runtime role; row-level security applies
#   n8n                 owner of the separate n8n database, no access to nexusflow
#
# Passwords are read from Docker secrets and passed as psql variables (quoted
# by psql with :'var'), never interpolated into SQL text.
set -eu

app_pw="$(cat /run/secrets/db_app_password)"
migrator_pw="$(cat /run/secrets/db_migrator_password)"
n8n_pw="$(cat /run/secrets/n8n_db_password)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
     -v app_pw="$app_pw" -v migrator_pw="$migrator_pw" -v n8n_pw="$n8n_pw" <<'EOSQL'
CREATE ROLE nexusflow_migrator LOGIN BYPASSRLS PASSWORD :'migrator_pw';
CREATE ROLE nexusflow_app LOGIN NOBYPASSRLS NOINHERIT CONNECTION LIMIT 150 PASSWORD :'app_pw';
CREATE ROLE n8n LOGIN NOBYPASSRLS CONNECTION LIMIT 30 PASSWORD :'n8n_pw';

CREATE DATABASE nexusflow OWNER nexusflow_migrator;
REVOKE ALL ON DATABASE nexusflow FROM PUBLIC;
GRANT CONNECT ON DATABASE nexusflow TO nexusflow_app;

CREATE DATABASE n8n OWNER n8n;
REVOKE ALL ON DATABASE n8n FROM PUBLIC;

-- Query statistics for operators (preloaded in docker-compose.yml; the view in
-- this maintenance database covers every database). Not in `nexusflow`: an
-- extension there belongs to the superuser, so restoring a backup as the
-- migrator (scripts/restore.sh) would fail on it.
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Session limits for the runtime role (defence against runaway queries).
ALTER ROLE nexusflow_app SET statement_timeout = '15s';
ALTER ROLE nexusflow_app SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE nexusflow_app SET lock_timeout = '5s';

\connect nexusflow
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO nexusflow_migrator;
GRANT USAGE ON SCHEMA public TO nexusflow_app;
EOSQL
