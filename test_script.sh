#!/bin/bash

# Create a fake eeprom file

fake_file="fake_eeprom.bin"
rm $fake_file 2>/dev/null
pos=0
while [ $pos -le 511 ] # key is at adress 0x400 , (1024/2) -1 
do
    echo -e "\x00" >> $fake_file
    pos=$(($pos + 1))
done 
echo -e "\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef" >> $fake_file

# Define test cases
declare -A tests=(
  ["test1"]="./sha256_challenge -K deadbeefdeadbeefdeadbeefdeadbeef -C BRHwwYS0yNi02ZC05ZS00MS0zMHxkZXZlbG9wZXJ8qrvM3e7/qqusra6vuru8vQ=="
  ["test2"]="./sha256_challenge -K deadbeefdeadbeefdeadbeefdeadbeef -C BRHwwYS0yNi02ZC05ZS00MS0zMHxkZXZlbG9wZXJ8qrvM3e7/qqusra6vuru8vQ== -i"
  ["test3"]="./sha256_challenge -F $fake_file -C BRHwwYS0yNi02ZC05ZS00MS0zMHxkZXZlbG9wZXJ8qrvM3e7/qqusra6vuru8vQ=="
  ["test4"]="./sha256_challenge -G 0a-26-6d-9e-41-30 -R aabbccddeeffaaabacadaeafbabbbcbd"
)

# Define expected outputs
declare -A expected=(
  ["test1"]="BqrvM3e7/qqusra6vuru8vVE9SXcLIGETiUhSoyd14GI8m0DnSCCP0I4qdk4jxZ2r"
  ["test2"]="Mac address: 0a-26-6d-9e-41-30
Developer answer: Cm7nkp2X4cMfKuw00a-26-6d-9e-41-30fqxWAIytIQt26vkU
Random number from mist: aabbccddeeffaaabacadaeafbabbbcbd
------------------------
Developer answer: BqrvM3e7/qqusra6vuru8vVE9SXcLIGETiUhSoyd14GI8m0DnSCCP0I4qdk4jxZ2r"
  ["test3"]="BqrvM3e7/qqusra6vuru8vVE9SXcLIGETiUhSoyd14GI8m0DnSCCP0I4qdk4jxZ2r"
  ["test4"]="BRHwwYS0yNi02ZC05ZS00MS0zMHxkZXZlbG9wZXJ8qrvM3e7/qqusra6vuru8vQ=="
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

rm $fake_file
echo "Tests complete: $passed passed, $failed failed"