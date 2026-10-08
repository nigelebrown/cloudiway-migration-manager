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

echo "[full-test] All checks passed"
