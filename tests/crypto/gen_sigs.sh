#!/bin/bash
if ! [ -d "tests/crypto/sigs" ]; then
  mkdir tests/crypto/sigs
fi

# Sign Keys
sudo seabeectl sign -t tests/crypto/keys/rsa-public.pem -k tests/crypto/keys/ecdsa-private.pem -o tests/crypto/sigs/rsa-public.sign
sudo seabeectl sign -t tests/crypto/keys/ecdsa-public.pem -k tests/crypto/keys/rsa-private.pem -o tests/crypto/sigs/ecdsa-public.sign

# Sign Policies
## Basic policy
sudo seabeectl sign -t tests/policies/test_policy.yaml -k tests/crypto/keys/ecdsa-private.pem -o tests/crypto/sigs/test-policy-ecdsa.sign
sudo seabeectl sign -t tests/policies/test_policy.yaml -k tests/crypto/keys/rsa-private.pem -o tests/crypto/sigs/test-policy-rsa.sign

## policy update
sudo seabeectl sign -t tests/policies/test_policy_v2.yaml -k tests/crypto/keys/ecdsa-private.pem -o tests/crypto/sigs/test-policy-v2-ecdsa.sign
sudo seabeectl sign -t tests/policies/test_policy_v2.yaml -k tests/crypto/keys/rsa-private.pem -o tests/crypto/sigs/test-policy-v2-rsa.sign

## policy with different digest
sudo seabeectl sign -t tests/policies/test_policy_sha256.yaml -k tests/crypto/keys/ecdsa-private.pem -o tests/crypto/sigs/test-policy-ecdsa-sha256.sign
sudo seabeectl sign -t tests/policies/test_policy_sha256.yaml -k tests/crypto/keys/rsa-private.pem -o tests/crypto/sigs/test-policy-rsa-sha256.sign

## policy removal
sudo seabeectl sign -t tests/policies/remove_test_policy.yaml -k tests/crypto/keys/ecdsa-private.pem -o tests/crypto/sigs/remove-test-policy-ecdsa.sign
sudo seabeectl sign -t tests/policies/remove_test_policy.yaml -k tests/crypto/keys/rsa-private.pem -o tests/crypto/sigs/remove-test-policy-rsa.sign
