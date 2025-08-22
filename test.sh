#!/bin/bash

set -euo pipefail

go test -v -cover -timeout 2s ./...