#!/usr/bin/env bash
# Install the edge's TLS certificate for nginx and reload it without downtime.
#
#   scripts/install_edge_cert.sh /etc/letsencrypt/live/<domain>     # by hand
#   certbot certonly --webroot -w ./deploy/acme -d <domain> \
#     --deploy-hook "$PWD/scripts/install_edge_cert.sh"             # and on every renewal
#
# certbot passes the renewed lineage in RENEWED_LINEAGE; by hand, pass the
# directory holding fullchain.pem and privkey.pem. The files are copied - not
# linked: Let's Encrypt's live/ entries are relative symlinks, which dangle
# inside the container - into NEXUSFLOW_TLS_DIR (default ./deploy/certs),
# readable by nginx's unprivileged user (uid 101) and nobody else, and nginx
# reloads them. Run as root (certbot's hooks do): only root can hand the key
# to uid 101.
set -euo pipefail

source="${RENEWED_LINEAGE:-${1:?usage: install_edge_cert.sh <directory with fullchain.pem and privkey.pem>}}"
cd "$(dirname "$0")/.."
target="${NEXUSFLOW_TLS_DIR:-./deploy/certs}"
nginx_uid=101  # nginxinc/nginx-unprivileged

for name in fullchain.pem privkey.pem; do
  [[ -s "${source}/${name}" ]] || { echo "missing ${source}/${name}" >&2; exit 1; }
done
mkdir -p "${target}"
# Write new files next to the old ones, then swap them in: nginx never sees a
# half-written key or a key that does not match its certificate.
install -m 0644 -o "${nginx_uid}" -g "${nginx_uid}" \
  "${source}/fullchain.pem" "${target}/.fullchain.pem.new"   # install copies a link's target
install -m 0600 -o "${nginx_uid}" -g "${nginx_uid}" \
  "${source}/privkey.pem" "${target}/.privkey.pem.new"
mv -f "${target}/.fullchain.pem.new" "${target}/fullchain.pem"
mv -f "${target}/.privkey.pem.new" "${target}/privkey.pem"

if docker compose ps --status running --services 2>/dev/null | grep -qx nginx; then
  docker compose exec -T nginx nginx -t
  docker compose exec -T nginx nginx -s reload
  echo "certificate installed and nginx reloaded"
else
  echo "certificate installed; start the stack to use it"
fi
