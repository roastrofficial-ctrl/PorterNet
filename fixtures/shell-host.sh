#!/bin/sh
set -eu
input=${1:?usage: shell-host INPUT OUTPUT}
output=${2:?usage: shell-host INPUT OUTPUT}
# Deliberately does not parse a PORTER Package or claim disposition.
digest=$(sha256sum "$input" | cut -d ' ' -f 1)
temporary="${output}.tmp"
printf '{"application":"opaque-shell-fixture","input_sha256":"%s"}\n' "$digest" > "$temporary"
mv "$temporary" "$output"
