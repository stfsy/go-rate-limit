#!/bin/bash

set -euo pipefail

go test -fuzz=FuzzGetClientIP -fuzztime=120s
go test -fuzz=FuzzAllow -fuzztime=240s

go test -fuzz=FuzzGetClientIP -race -fuzztime=20s
go test -fuzz=FuzzAllow -race -fuzztime=20s