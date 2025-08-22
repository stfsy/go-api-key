#/bin/bash

set -euo pipefail

MSYS_NO_PATHCONV=1 docker run --rm \
--mount type=bind,src=.,dst=/app \
-w /app golangci/golangci-lint:v2.0 golangci-lint \
run -v
