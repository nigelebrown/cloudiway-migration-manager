#!/usr/bin/env bash
set -Eeuo pipefail

echo "[full-test] Dependency check"
python -m pip check

echo "[full-test] Python compile check"
python -m compileall -q app

echo "[full-test] Installer/update shell syntax"
bash -n install-centos.sh
bash -n update-centos.sh

echo "[full-test] Application/unit/integration workflow tests"
pytest -q

echo "[full-test] Live HTTP smoke test"
SMOKE_LOG="${TMPDIR:-/tmp}/cloudiway-smoke.log"
uvicorn app.main:app --host 127.0.0.1 --port 18080 >"${SMOKE_LOG}" 2>&1 &
SMOKE_PID=$!
cleanup_smoke(){
  kill "${SMOKE_PID}" >/dev/null 2>&1 || true
  wait "${SMOKE_PID}" >/dev/null 2>&1 || true
}
trap cleanup_smoke EXIT

healthy=0
for _ in {1..30}; do
  if curl -fsS http://127.0.0.1:18080/health >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 1
done
if [[ "${healthy}" -ne 1 ]]; then
  cat "${SMOKE_LOG}" >&2 || true
  exit 1
fi
curl -fsS http://127.0.0.1:18080/ >/dev/null
cleanup_smoke
trap - EXIT

echo "[full-test] All checks passed"
