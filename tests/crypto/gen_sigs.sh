#!/bin/bash
if ! [ -d "crypto/sigs" ]; then
  mkdir crypto/sigs
fi

# Sign Keys
sudo seabeectl sign -t crypto/keys/rsa-public.pem -k ../seabee-root-private-key.pem -o crypto/sigs/rsa-public-root-sig.sign --nopass
sudo seabeectl sign -t crypto/keys/ecdsa-public.pem -k ../seabee-root-private-key.pem -o crypto/sigs/ecdsa-public-root-sig.sign --nopass
sudo seabeectl sign -t crypto/keys/ecdsa-public.pem -k crypto/keys/ecdsa-private.pem -o crypto/sigs/ecdsa-public-ecdsa-sig.sign --nopass

# Sign Policies
## Basic policy
sudo seabeectl sign -t policies/test_policy.yaml -k crypto/keys/ecdsa-private.pem -o crypto/sigs/test-policy-ecdsa.sign --nopass
sudo seabeectl sign -t policies/test_policy.yaml -k crypto/keys/rsa-private.pem -o crypto/sigs/test-policy-rsa.sign --nopass

## policy update
sudo seabeectl sign -t policies/test_policy_v2.yaml -k crypto/keys/ecdsa-private.pem -o crypto/sigs/test-policy-v2-ecdsa.sign --nopass
sudo seabeectl sign -t policies/test_policy_v2.yaml -k crypto/keys/rsa-private.pem -o crypto/sigs/test-policy-v2-rsa.sign --nopass

## policy with different digest
sudo seabeectl sign -t policies/test_policy_sha256.yaml -k crypto/keys/ecdsa-private.pem -o crypto/sigs/test-policy-ecdsa-sha256.sign --nopass
sudo seabeectl sign -t policies/test_policy_sha256.yaml -k crypto/keys/rsa-private.pem -o crypto/sigs/test-policy-rsa-sha256.sign --nopass

## test policy
sudo seabeectl sign -t policies/test_tool_debug_policy.yaml -k crypto/keys/rsa-private.pem -o crypto/sigs/test-tool-debug-policy.sign --nopass
sudo seabeectl sign -t policies/test_tool_release_policy.yaml -k crypto/keys/rsa-private.pem -o crypto/sigs/test-tool-release-policy.sign --nopass

## policy removal
sudo seabeectl sign -t policies/remove_test_policy.yaml -k crypto/keys/ecdsa-private.pem -o crypto/sigs/remove-test-policy-ecdsa.sign --nopass
sudo seabeectl sign -t policies/remove_test_policy_v2.yaml -k crypto/keys/ecdsa-private.pem -o crypto/sigs/remove-test-policy-v2-ecdsa.sign --nopass

sudo seabeectl sign -t policies/remove_test_policy.yaml -k crypto/keys/rsa-private.pem -o crypto/sigs/remove-test-policy-rsa.sign --nopass
