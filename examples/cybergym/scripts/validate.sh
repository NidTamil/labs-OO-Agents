#!/usr/bin/env bash
#
# Post-validate the PoCs an agent submitted: replay each one against the fixed
# build and fill in fix_exit_code in the server's poc.db, then print a summary.
#
# Usage:
#   scripts/validate.sh [RUN_DIR] [--cohort-manifest PATH]
#     [--cohort-commitment PATH] [--cohort-authority-keys PATH]
#
# RUN_DIR defaults to the most recent runs/validation_10task_* directory. Pass a
# path to validate a different run (e.g. runs/logs for a single-task run).
#
# Requires the CyberGym server (scripts/start_server.sh) to be running.
#
set -euo pipefail
source "$(dirname "$0")/config.sh"
activate_venv

if [ -z "${CYBERGYM_API_KEY:-}" ]; then
  echo "CYBERGYM_API_KEY is not set. Run scripts/setup.sh first (it generates one in .env)." >&2
  echo "It must match the key the running server was started with." >&2
  exit 1
fi
# verify_agent_result.py reads CYBERGYM_API_KEY from the environment.
export CYBERGYM_API_KEY

RUN_DIR=""
COHORT_MANIFEST=""
COHORT_COMMITMENT=""
COHORT_AUTHORITY_KEYS=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cohort-manifest)
      if [ "$#" -lt 2 ]; then
        echo "--cohort-manifest requires a path" >&2
        exit 2
      fi
      COHORT_MANIFEST="$2"
      shift 2
      ;;
    --cohort-commitment)
      if [ "$#" -lt 2 ]; then
        echo "--cohort-commitment requires a path" >&2
        exit 2
      fi
      COHORT_COMMITMENT="$2"
      shift 2
      ;;
    --cohort-authority-keys)
      if [ "$#" -lt 2 ]; then
        echo "--cohort-authority-keys requires a path" >&2
        exit 2
      fi
      COHORT_AUTHORITY_KEYS="$2"
      shift 2
      ;;
    --*)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
    *)
      if [ -n "$RUN_DIR" ]; then
        echo "Only one run directory may be supplied" >&2
        exit 2
      fi
      RUN_DIR="$1"
      shift
      ;;
  esac
done
RUN_DIR="${RUN_DIR:-$(ls -td "$AGENT_REPO"/runs/validation_10task_* 2>/dev/null | head -1 || true)}"
if [ -z "${RUN_DIR:-}" ] || [ ! -d "$RUN_DIR" ]; then
  echo "No run directory found. Pass one explicitly: scripts/validate.sh <run-dir>" >&2
  exit 1
fi

# Classify the complete run root before contacting the verifier. This prevents
# partially verified mixed-mode roots from being mistaken for official cohorts.
classifier_args=("$RUN_DIR")
if [ -n "$COHORT_MANIFEST" ]; then
  classifier_args+=(--cohort-manifest "$COHORT_MANIFEST")
fi
if [ -n "$COHORT_COMMITMENT" ]; then
  classifier_args+=(--cohort-commitment "$COHORT_COMMITMENT")
fi
if [ -n "$COHORT_AUTHORITY_KEYS" ]; then
  classifier_args+=(--cohort-authority-keys "$COHORT_AUTHORITY_KEYS")
fi
validation_plan=$(
  python3 "$AGENT_REPO/nooa_cybergym/validation_modes.py" "${classifier_args[@]}"
)
VALIDATION_MODE=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["mode"])' <<<"$validation_plan")
mapfile -t args_files < <(
  python3 -c 'import json,sys; print(*json.load(sys.stdin)["args_files"], sep="\n")' \
    <<<"$validation_plan"
)

POC_DB="$CYBERGYM_POC_DB"
if [ ! -f "$POC_DB" ]; then
  echo "CyberGym PoC database not found at $POC_DB." >&2
  echo "Set CYBERGYM_POC_DB to the database used by the running task server." >&2
  exit 1
fi
echo "==> Validating runs under $RUN_DIR"

for args in "${args_files[@]}"; do
  agent_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["agent_id"])' "$args")
  echo "==> verifying agent_id=$agent_id"
  # verify_agent_result.py POSTs to /verify-agent-pocs (using $CYBERGYM_API_KEY)
  # to run the fixed-build check, then prints each PoC record from the DB.
  python3 "$CYBERGYM_REPO/scripts/verify_agent_result.py" \
    --server "$CYBERGYM_SERVER" \
    --pocdb_path "$POC_DB" \
    --agent_id "$agent_id"
done

if [ "$VALIDATION_MODE" = "diagnostic" ]; then
  echo
  echo "==> Diagnostic validation complete; official evidence is intentionally not signed"
  exit 0
fi

echo
echo "==> Scoring frozen final PoCs and writing signed evidence"
if [ ! -d "$XEUS_CYBERGYM_REPO/src/xeus_cybergym" ]; then
  echo "Xeus CyberGym authority code not found at $XEUS_CYBERGYM_REPO" >&2
  exit 1
fi
scorer_args=(
  --run-dir "$RUN_DIR"
  --poc-db "$POC_DB"
  --output-dir "$RUN_DIR/official_evidence"
)
if [ "$VALIDATION_MODE" = "legacy" ]; then
  scorer_args+=(--allow-legacy-single-run)
else
  scorer_args+=(--cohort-manifest "$COHORT_MANIFEST")
  if [ -n "$COHORT_COMMITMENT" ]; then
    scorer_args+=(--cohort-commitment "$COHORT_COMMITMENT")
  fi
  if [ -n "$COHORT_AUTHORITY_KEYS" ]; then
    scorer_args+=(--cohort-authority-keys "$COHORT_AUTHORITY_KEYS")
  fi
fi
PYTHONPATH="$CYBERGYM_REPO/src:$XEUS_CYBERGYM_REPO/src${PYTHONPATH:+:$PYTHONPATH}" \
  python3 "$AGENT_REPO/scripts/score_final.py" \
    "${scorer_args[@]}"
