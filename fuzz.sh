#!/bin/bash

set -euo pipefail

go test -fuzz=FuzzCreateHashUnique -fuzztime=120s
go test -fuzz=FuzzComparePasswordAndHash -fuzztime=120s