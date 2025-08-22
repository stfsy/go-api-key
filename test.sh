#!/bin/bash

set -euo pipefail

go test -v -cover -timeout 10s ./...