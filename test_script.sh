#!/bin/bash

# Define test cases
declare -A tests=(
  ["test1"]="./sha256_challenge -K deadbeefdeadbeefdeadbeefdeadbeef -C BRHwwYS0yNi02ZC05ZS00MS0zMHxkZXZlbG9wZXJ8qrvM3e7/qqusra6vuru8vQ=="
  ["test2"]="./sha256_challenge -K deadbeefdeadbeefdeadbeefdeadbeef -C BRHwwYS0yNi02ZC05ZS00MS0zMHxkZXZlbG9wZXJ8qrvM3e7/qqusra6vuru8vQ== -i"
  ["test3"]="./sha256_challenge -G 00:11:22:33:44:55 -R aabbccddeeffaaabacadaeafbabbbcbd"
)

# Define expected outputs
declare -A expected=(
  ["test1"]="BqrvM3e7/qqusra6vuru8vVE9SXcLIGETiUhSoyd14GI8m0DnSCCP0I4qdk4jxZ2r"
  ["test2"]="Mac address: 0a-26-6d-9e-41-30
Challenge answer: Cm7nkp2X4cMfKuw00a-26-6d-9e-41-30fqxWAIytIQt26vkU
Random number from mist: aabbccddeeffaaabacadaeafbabbbcbd
Developer Answer: BqrvM3e7/qqusra6vuru8vVE9SXcLIGETiUhSoyd14GI8m0DnSCCP0I4qdk4jxZ2r"
  ["test3"]="BRHwwMDoxMToyMjozMzo0NDo1NXxkZXZlbG9wZXJ8qrvM3e7/qqusra6vuru8vQ=="
)

# Run tests
passed=0
failed=0

for test in "${!tests[@]}"; do
  echo "Running $test..."
  result=$(${tests[$test]})
  
  if [[ "$result" == "${expected[$test]}" ]]; then
    echo "PASSED"
    ((passed++))
  else
    echo "FAILED"
    echo "Expected: ${expected[$test]}"
    echo "Got: $result"
    ((failed++))
  fi
  echo "------------------------"
done

echo "Tests complete: $passed passed, $failed failed"