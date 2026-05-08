#!/bin/sh
target="$1"
shift
printf '%s\n' "$target" | /usr/bin/httpx-toolkit "$@"
