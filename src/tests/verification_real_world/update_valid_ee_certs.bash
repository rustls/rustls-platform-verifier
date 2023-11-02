#!/usr/bin/env bash

set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

fetch_ee_cert() {
  local domain="$1"
  local out_file="$2"

  echo -n |
    openssl s_client \
      -connect "$domain:443" \
      -servername "$domain" |
    openssl x509 \
      -outform DER > "$DIR/$out_file"
}

fetch_ee_cert "my.1password.com" "1password_com_valid_1.crt"
fetch_ee_cert "agilebits.com" "agilebits_com_valid_1.crt"
fetch_ee_cert "lencr.org" "letsencrypt_org_valid_1.crt"
