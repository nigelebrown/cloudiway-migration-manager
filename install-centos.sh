#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/cloudiway-migration-manager}"
REPO_URL="${REPO_URL:-https://github.com/nigelebrown/cloudiway-migration-manager.git}"
BRANCH="${BRANCH:-main}"

log(){ printf "\033[1;34m[cloudiway-install]\033[0m %s\n" "$*"; }
fail(){ printf "\033[1;31m[cloudiway-install]\033[0m %s\n" "$*" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
  fail "Run this installer as root: sudo bash install-centos.sh"
fi

if [[ ! -r /etc/os-release ]]; then
  fail "Cannot identify this Linux distribution."
fi
source /etc/os-release

case "${ID:-}" in
  centos|rhel|rocky|almalinux) ;;
  *)
    if [[ "${ID_LIKE:-}" != *"rhel"* ]]; then
      fail "This installer supports CentOS Stream / RHEL-compatible systems."
    fi
    ;;
esac

MAJOR="${VERSION_ID%%.*}"
if [[ "${MAJOR}" -lt 8 ]]; then
  fail "CentOS/RHEL 7 and older are not supported. Use CentOS Stream/RHEL/Rocky/Alma 8 or 9."
fi

log "Installing base packages..."
dnf -y install dnf-plugins-core git openssl curl ca-certificates

if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine..."
  dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null
  dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

log "Starting Docker..."
systemctl enable --now docker

if ! docker compose version >/dev/null 2>&1; then
  fail "Docker Compose plugin is not available after installation."
fi

if [[ -d "${APP_DIR}/.git" ]]; then
  log "Updating existing application in ${APP_DIR}..."
  git -C "${APP_DIR}" fetch origin "${BRANCH}"
  git -C "${APP_DIR}" checkout "${BRANCH}"
  git -C "${APP_DIR}" pull --ff-only origin "${BRANCH}"
else
  log "Cloning application to ${APP_DIR}..."
  mkdir -p "$(dirname "${APP_DIR}")"
  git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_DIR}"
fi

cd "${APP_DIR}"

rand_hex(){ openssl rand -hex "$1"; }

if [[ ! -f .env ]]; then
  log "Creating secure .env configuration..."
  APP_ADMIN_PASSWORD="${APP_ADMIN_PASSWORD:-$(rand_hex 12)}"
  APP_ENCRYPTION_KEY="${APP_ENCRYPTION_KEY:-$(rand_hex 32)}"
  SESSION_SECRET="${SESSION_SECRET:-$(rand_hex 32)}"
  DB_PASSWORD="${DB_PASSWORD:-$(rand_hex 18)}"
  MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-$(rand_hex 24)}"

  cat > .env <<EOF
APP_ADMIN_PASSWORD=${APP_ADMIN_PASSWORD}
APP_ENCRYPTION_KEY=${APP_ENCRYPTION_KEY}
SESSION_SECRET=${SESSION_SECRET}

DB_HOST=mysql
DB_PORT=3306
DB_NAME=cloudiway_migration
DB_USER=cloudiway
DB_PASSWORD=${DB_PASSWORD}
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}

CLOUDIWAY_BASE_URL=https://api-production.cloudiway.com/ap1
CLOUDIWAY_PROJECT_HEADER=JCF
CLOUDIWAY_PRODUCT_TYPE_MAIL=5
CLOUDIWAY_JOB_TYPE_AUDIT=30
CLOUDIWAY_JOB_TYPE_MIGRATION=33

RACKSPACE_BASE_URL=https://api.emailsrvr.com/v1

PILOT_SIZE=5
BATCH_SIZE=10
STATUS_POLL_SECONDS=15
PROGRESS_WINDOW_MINUTES=1
BATCH_TIMEOUT_MINUTES=1440
AUTO_CONTINUE=true
PAUSE_ON_ANY_FAILURE=true

# First-install convenience. Set to true after placing HTTPS in front of the app.
SESSION_HTTPS_ONLY=false
LOGIN_MAX_ATTEMPTS=5
LOGIN_WINDOW_SECONDS=300

APP_BIND=0.0.0.0
APP_PORT=8080
PHPMYADMIN_BIND=127.0.0.1
PHPMYADMIN_PORT=8081
EOF

  chmod 600 .env

  cat > INSTALL-CREDENTIALS.txt <<EOF
JCF Cloudiway Migration Manager - Initial Installation Credentials
Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

Application admin password:
${APP_ADMIN_PASSWORD}

MySQL application user:
cloudiway

MySQL application password:
${DB_PASSWORD}

MySQL root password:
${MYSQL_ROOT_PASSWORD}

IMPORTANT:
- Protect this file and delete it after recording the credentials securely.
- phpMyAdmin is bound to 127.0.0.1 by default.
- SESSION_HTTPS_ONLY is false only for initial HTTP testing. Enable HTTPS, then set it to true.
EOF
  chmod 600 INSTALL-CREDENTIALS.txt
else
  log ".env already exists; preserving existing secrets and settings."
fi

if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
  log "Opening application port 8080/tcp in firewalld..."
  firewall-cmd --permanent --add-port=8080/tcp >/dev/null
  firewall-cmd --reload >/dev/null
fi

log "Building and starting MySQL, phpMyAdmin, and the migration app..."
docker compose up -d --build

log "Waiting for application health..."
for i in {1..60}; do
  if curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

if ! curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; then
  docker compose ps
  docker compose logs --tail=100 app
  fail "Application did not become healthy. Review the logs above."
fi

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
SERVER_IP="${SERVER_IP:-SERVER-IP}"

cat <<EOF

Installation complete.

Migration application:
  http://${SERVER_IP}:8080

phpMyAdmin:
  Bound to localhost only for safety.
  From the server: http://127.0.0.1:8081

Initial credentials:
  ${APP_DIR}/INSTALL-CREDENTIALS.txt

Useful commands:
  cd ${APP_DIR}
  docker compose ps
  docker compose logs -f app
  docker compose restart
  docker compose down

Security before live migration:
  1. Put the app behind HTTPS.
  2. Change SESSION_HTTPS_ONLY=true in .env.
  3. Keep phpMyAdmin restricted to localhost/VPN or an admin-only network.
  4. Delete INSTALL-CREDENTIALS.txt after storing the credentials securely.

EOF
