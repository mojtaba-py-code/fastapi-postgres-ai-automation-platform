#!/usr/bin/env bash
# Encrypted backup of the NexusFlow databases and file storage.
#
#   BACKUP_AGE_RECIPIENT=age1... scripts/backup.sh [backup-dir]
#
# * PostgreSQL: pg_dump (custom format) of `nexusflow` and `n8n`;
# * files: the nexusflow-data volume (uploads, reports);
# * every artifact is encrypted with age to BACKUP_AGE_RECIPIENT before it
#   touches the disk - unencrypted backups are refused;
# * a SHA-256 manifest lets restore.sh verify integrity first; with
#   BACKUP_SIGNING_KEY (an SSH private key, kept off the backup store) the
#   manifest is also signed, so restore.sh can verify where it came from.
# Secrets (./secrets) are NOT included: back them up separately, offline.
set -euo pipefail

: "${BACKUP_AGE_RECIPIENT:?set BACKUP_AGE_RECIPIENT (age public key) - backups are always encrypted}"
command -v age >/dev/null || { echo "age is required (https://age-encryption.org)" >&2; exit 1; }

# Runs a PostgreSQL client tool inside the postgres container as the superuser.
# Local connections need a password (scram-sha-256); it is read from the
# container's own secret there and never passes through this host's commands.
pg() {
  docker compose exec -T postgres \
    sh -c 'PGPASSWORD="$(cat /run/secrets/postgres_password)" exec "$@"' sh "$@"
}

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="${1:-backups}/${stamp}"
umask 077
mkdir -p "${target}"

for db in nexusflow n8n; do
  echo "dumping ${db}..."
  pg pg_dump -U postgres --format=custom --no-owner "${db}" \
    | age -r "${BACKUP_AGE_RECIPIENT}" -o "${target}/${db}.dump.age"
done

echo "archiving file storage..."
docker compose run --rm --no-deps -T --entrypoint tar api -C /var/lib/nexusflow -cf - . \
  | age -r "${BACKUP_AGE_RECIPIENT}" -o "${target}/files.tar.age"

(cd "${target}" && sha256sum ./*.age > SHA256SUMS)
if [[ -n "${BACKUP_SIGNING_KEY:-}" ]]; then
  ssh-keygen -Y sign -q -f "${BACKUP_SIGNING_KEY}" -n nexusflow-backup "${target}/SHA256SUMS"
fi
echo "backup written to ${target}"
