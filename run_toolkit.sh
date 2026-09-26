#!/usr/bin/env bash
set -u
cd "$(dirname "$(realpath "$0")")"
exec python3 toolkit.py "$@"
