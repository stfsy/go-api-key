#!/bin/bash

set -euo pipefail

go test -fuzz=FuzzGetTokenComponents -fuzztime=30s
go test -fuzz=FuzzExtractShortToken -fuzztime=30s
go test -fuzz=FuzzExtractLongToken -fuzztime=30s
go test -fuzz=FuzzCheckAPIKey -fuzztime=30s
go test -fuzz=FuzzArgon2IdHasher_HashAndVerify -fuzztime=30s