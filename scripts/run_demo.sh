#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PATH="${VENV_PATH:-$HOME/.venvs/ryu310}"

if [[ ! -x "$VENV_PATH/bin/python" ]]; then
  echo "Virtual environment not found at $VENV_PATH"
  echo "Create it first, then install dependencies from requirements.txt"
  exit 1
fi

source "$VENV_PATH/bin/activate"
export PYTHONNOUSERSITE=1
export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"

mkdir -p "$PROJECT_ROOT/logs"

sudo mn -c >/dev/null 2>&1 || true

python "$PROJECT_ROOT/controller/run_controller.py" \
  "$PROJECT_ROOT/controller/dynamic_host_blocking.py" \
  >"$PROJECT_ROOT/logs/controller_stdout.log" 2>&1 &
CTRL_PID=$!

cleanup() {
  kill "$CTRL_PID" >/dev/null 2>&1 || true
  sudo mn -c >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2

if ! kill -0 "$CTRL_PID" >/dev/null 2>&1; then
  echo "Controller failed to start. Recent log output:"
  tail -n 80 "$PROJECT_ROOT/logs/controller_stdout.log" || true
  exit 1
fi

echo "Controller started (PID=$CTRL_PID)."
echo "Open another terminal to watch logs: tail -f $PROJECT_ROOT/logs/block_events.log"
echo "Launching Mininet topology..."

sudo -E python3 "$PROJECT_ROOT/topology/dynamic_topology.py" \
  --controller-ip 127.0.0.1 \
  --controller-port 6653
