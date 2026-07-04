#!/usr/bin/env bash
# Lightweight eval harness: prints the trigger + output eval tables so a human or
# an agent-judge can score description routing and capability selection. (These
# are judgement evals — there is no automated grader for natural-language routing.)
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "### TRIGGER EVALS ###"; cat "$HERE/trigger-evals.md"
echo; echo "### OUTPUT EVALS ###"; cat "$HERE/output-evals.md"
