#!/bin/bash
set -euo pipefail

echo 'This script only updates 1password_com_valid_1.crt'
echo 'It can likely be extended to download the whole chain.'

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo -n | openssl s_client -connect my.1password.com:443 -servername my.1password.com \
    | openssl x509 -outform DER > "$DIR/1password_com_valid_1.crt"
