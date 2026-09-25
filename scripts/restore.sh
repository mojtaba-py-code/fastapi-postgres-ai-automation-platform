#!/usr/bin/env bash
# Restore a backup made by backup.sh into a STOPPED application stack.
#
#   BACKUP_AGE_IDENTITY=~/.config/age/key.txt scripts/restore.sh backups/<stamp>
#
# Verifies the SHA-256 manifest before decrypting anything. The database
# restore replaces existing objects; take a fresh backup first. Automation can
# confirm on standard input: `echo RESTORE | scripts/restore.sh <dir>`.
set -euo pipefail

source_dir="${1:?usage: restore.sh <backup-dir>}"
: "${BACKUP_AGE_IDENTITY:?set BACKUP_AGE_IDENTITY (age private key file)}"

# Runs a PostgreSQL client tool inside the postgres container as the superuser
# (the password is read from the container's own secret, see backup.sh).
pg() {
  docker compose exec -T postgres \
    sh -c 'PGPASSWORD="$(cat /run/secrets/postgres_password)" exec "$@"' sh "$@"
}

(cd "${source_dir}" && sha256sum --check --strict SHA256SUMS)

read -r -p "This overwrites the nexusflow and n8n databases and all stored files. Type RESTORE: " answer
[[ "${answer}" == "RESTORE" ]] || { echo "aborted"; exit 1; }

docker compose stop api api-internal worker-pipeline worker-integrations beat sandbox n8n

# Objects are recreated as their usual owners, so later migrations still work;
# any error aborts the restore (pg_restore exits non-zero when it skipped one).
for db in nexusflow n8n; do
  echo "restoring ${db}..."
  age -d -i "${BACKUP_AGE_IDENTITY}" "${source_dir}/${db}.dump.age" \
    | pg pg_restore -U postgres --clean --if-exists --no-owner \
        --role="$([[ ${db} == n8n ]] && echo n8n || echo nexusflow_migrator)" -d "${db}"
done

echo "restoring file storage..."
age -d -i "${BACKUP_AGE_IDENTITY}" "${source_dir}/files.tar.age" \
  | docker compose run --rm --no-deps -T --entrypoint tar api -C /var/lib/nexusflow -xf -

echo "done - start the stack and run: docker compose run --rm api nexusflow audit verify"
