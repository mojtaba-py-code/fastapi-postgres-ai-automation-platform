#!/usr/bin/env bash
# Restore a backup made by backup.sh into a STOPPED application stack.
#
#   BACKUP_AGE_IDENTITY=~/.config/age/key.txt scripts/restore.sh backups/<stamp>
#
# Verifies the SHA-256 manifest before decrypting anything - and, with
# BACKUP_ALLOWED_SIGNERS (an ssh-keygen allowed-signers file naming the
# principal "nexusflow-backup"), that the manifest was signed by backup.sh: a
# hash list alone proves integrity, not origin. The database restore replaces
# existing objects; take a fresh backup first. Automation can confirm on
# standard input: `echo RESTORE | scripts/restore.sh <dir>`.
set -euo pipefail

source_dir="${1:?usage: restore.sh <backup-dir>}"
: "${BACKUP_AGE_IDENTITY:?set BACKUP_AGE_IDENTITY (age private key file)}"

# Runs a PostgreSQL client tool inside the postgres container as ROLE, with the
# role's own password (mounted there as a secret) - never as the superuser, so
# a tampered dump cannot RESET ROLE and run code (COPY ... TO PROGRAM).
pg_as() {
  local role="$1" secret="$2"
  shift 2
  docker compose exec -T -e PGUSER="${role}" -e PGSECRET="${secret}" postgres \
    sh -c 'PGPASSWORD="$(cat "/run/secrets/${PGSECRET}")" exec "$@"' sh "$@"
}

if [[ -n "${BACKUP_ALLOWED_SIGNERS:-}" ]]; then
  ssh-keygen -Y verify -f "${BACKUP_ALLOWED_SIGNERS}" -I nexusflow-backup -n nexusflow-backup \
    -s "${source_dir}/SHA256SUMS.sig" < "${source_dir}/SHA256SUMS"
else
  echo "warning: BACKUP_ALLOWED_SIGNERS is not set - the manifest's origin is not verified" >&2
fi
(cd "${source_dir}" && sha256sum --check --strict SHA256SUMS)

read -r -p "This overwrites the nexusflow and n8n databases and all stored files. Type RESTORE: " answer
[[ "${answer}" == "RESTORE" ]] || { echo "aborted"; exit 1; }

docker compose stop api api-internal worker-pipeline worker-integrations beat sandbox n8n

# Each database is restored by its owner, so objects keep their usual owners
# and later migrations still work; any error aborts the restore (pg_restore
# exits non-zero when it skipped one).
echo "restoring nexusflow..."
age -d -i "${BACKUP_AGE_IDENTITY}" "${source_dir}/nexusflow.dump.age" \
  | pg_as nexusflow_migrator db_migrator_password \
      pg_restore --clean --if-exists --no-owner -d nexusflow
echo "restoring n8n..."
age -d -i "${BACKUP_AGE_IDENTITY}" "${source_dir}/n8n.dump.age" \
  | pg_as n8n n8n_db_password pg_restore --clean --if-exists --no-owner -d n8n

echo "restoring file storage..."
age -d -i "${BACKUP_AGE_IDENTITY}" "${source_dir}/files.tar.age" \
  | docker compose run --rm --no-deps -T --entrypoint tar api -C /var/lib/nexusflow -xf -

echo "done - start the stack and run: docker compose run --rm api nexusflow audit verify"
