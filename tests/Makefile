TEST_SERVICE = test_seabee.service
TEST_SERVICE_SRC = $(TEST_SERVICE)
TEST_SERVICE_PATH = /etc/systemd/system/$(TEST_SERVICE)

.PHONY: all test test-release test-policy test-policy-release example-kmod test-kmod

# if missing or outdated, install a new daemon test service into systemd
$(TEST_SERVICE_PATH): $(TEST_SERVICE_SRC)
	sudo cp $(TEST_SERVICE_SRC) $(TEST_SERVICE_PATH)
	sudo systemctl daemon-reload

generate-test-sigs:
	@./crypto/gen_sigs.sh

# run tests with debug binaries
test: integration-test policy-test

# run tests with release binaries
test-release: integration-test-release policy-test-release

integration-test: example-kmod test-kmod
	sudo ../target/debug/integration_test

integration-test-release: example-kmod test-kmod
	sudo ../target/release/integration_test

# launch and test seabee policy with debug binaries
policy-test: $(TEST_SERVICE_PATH) generate-test-sigs
	sudo ../target/debug/policy_test --test-threads=1

# launch and test seabee policy with release binaries
policy-test-release: $(TEST_SERVICE_PATH) generate-test-sigs
	sudo ../target/release/policy_test --test-threads=1

# compile and compress 'example_kmod/hello_world_kmod.c'
example-kmod:
	@make -C kmod_example test

# remove, compile, and reinstall 'test_kmod/test_kmod.c'
# also compile 'test_kmod/test_kmod_user.c'
test-kmod:
	@make -C kmod_test test
