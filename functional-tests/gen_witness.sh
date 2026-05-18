#!/usr/bin/env bash
set -e

# should compile move from https://github.com/zkmove/move.git#branch=main
MOVE="move"
$MOVE build --skip-fetch-latest-git-deps
$MOVE sandbox clean
$MOVE sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes

# Read test cases from a file
test_cases_file="test_cases.txt"
if [ ! -f "$test_cases_file" ]; then
    echo "Error: $test_cases_file not found"
    exit 1
fi

while IFS= read -r test_case || [[ -n "$test_case" ]]; do
    $MOVE sandbox run --skip-fetch-latest-git-deps --witness storage/0x0000000000000000000000000000000000000000000000000000000000000002/modules/TestCase.mv $test_case
done < "$test_cases_file"
