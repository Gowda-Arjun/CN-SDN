#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PATH="${VENV_PATH:-$HOME/.venvs/ryu310}"

if ! command -v python3.10 >/dev/null 2>&1; then
  echo "python3.10 is required. Install it first: sudo pacman -S python310"
  exit 1
fi

python3.10 -m venv --clear "$VENV_PATH"
source "$VENV_PATH/bin/activate"

python -m pip install --upgrade pip==24.3.1 setuptools==65.5.0 wheel==0.45.1
python -m pip install --upgrade --no-build-isolation -r "$PROJECT_ROOT/requirements.txt"

echo "Environment ready at $VENV_PATH"
python - <<'PY'
from importlib import metadata

print("eventlet", metadata.version("eventlet"))
print("ryu", metadata.version("ryu"))
PY
