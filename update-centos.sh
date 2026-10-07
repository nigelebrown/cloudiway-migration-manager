#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/cloudiway-migration-manager}"
BRANCH="${BRANCH:-main}"

log(){ printf "\033[1;34m[cloudiway-update]\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m[cloudiway-update]\033[0m %s\n" "$*" >&2; }
fail(){ printf "\033[1;31m[cloudiway-update]\033[0m %s\n" "$*" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
  fail "Run as root: sudo bash update-centos.sh"
fi

[[ -d "${APP_DIR}/.git" ]] || fail "Application not found at ${APP_DIR}. Run install-centos.sh first."
cd "${APP_DIR}"

command -v git >/dev/null 2>&1 || fail "git is not installed."
command -v docker >/dev/null 2>&1 || fail "docker is not installed."
docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is not installed."

OLD_COMMIT="$(git rev-parse HEAD)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p backups

log "Creating MySQL backup before update..."
if docker compose ps --status running mysql 2>/dev/null | grep -q mysql; then
  if docker compose exec -T mysql sh -c 'exec mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --triggers "$MYSQL_DATABASE"' > "backups/cloudiway-${STAMP}.sql"; then
    gzip "backups/cloudiway-${STAMP}.sql"
    log "Backup saved to backups/cloudiway-${STAMP}.sql.gz"
  else
    rm -f "backups/cloudiway-${STAMP}.sql"
    fail "Database backup failed. Update aborted."
  fi
else
  warn "MySQL container is not currently running. No database backup was created."
fi

log "Fetching latest ${BRANCH}..."
git fetch origin "${BRANCH}"
git checkout "${BRANCH}"
git reset --hard "origin/${BRANCH}"
NEW_COMMIT="$(git rev-parse HEAD)"

if [[ "${OLD_COMMIT}" == "${NEW_COMMIT}" ]]; then
  log "Application is already up to date (${NEW_COMMIT:0:12})."
else
  log "Updating ${OLD_COMMIT:0:12} -> ${NEW_COMMIT:0:12}"
fi

log "Rebuilding and restarting stack..."
if ! docker compose up -d --build --remove-orphans; then
  warn "Docker Compose update failed. Rolling back code."
  git reset --hard "${OLD_COMMIT}"
  docker compose up -d --build --remove-orphans || true
  fail "Update failed and code was rolled back to ${OLD_COMMIT:0:12}."
fi

log "Waiting for application health..."
healthy=0
for i in {1..90}; do
  if curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 2
done

if [[ "${healthy}" -ne 1 ]]; then
  warn "New version failed health check. Showing recent logs:"
  docker compose logs --tail=120 app || true
  warn "Rolling back to previous version ${OLD_COMMIT:0:12}..."
  git reset --hard "${OLD_COMMIT}"
  docker compose up -d --build --remove-orphans || true
  fail "Update failed health check and was rolled back."
fi

# Keep the latest 10 compressed database backups.
ls -1t backups/cloudiway-*.sql.gz 2>/dev/null | tail -n +11 | xargs -r rm -f

log "Update completed successfully."
echo
echo "Current version: ${NEW_COMMIT}"
echo "Application: http://$(hostname -I 2>/dev/null | awk '{print $1}'):8080"
echo
echo "Useful commands:"
echo "  cd ${APP_DIR}"
echo "  docker compose ps"
echo "  docker compose logs -f app"
echo
