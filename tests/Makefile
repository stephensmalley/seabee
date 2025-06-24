TEST_SERVICE = test_seabee.service
TEST_SERVICE_SRC = $(TEST_SERVICE)
TEST_SERVICE_PATH = /etc/systemd/system/$(TEST_SERVICE)

.PHONY: all test test-release test-daemon test-daemon-release example-kmod test-kmod

# if missing or outdated, install a new daemon test service into systemd
$(TEST_SERVICE_PATH): $(TEST_SERVICE_SRC)
	sudo cp $(TEST_SERVICE_SRC) $(TEST_SERVICE_PATH)
	sudo systemctl daemon-reload

# run tests with debug binaries
test: example-kmod test-kmod test-daemon
	sudo ../target/debug/integration_test

# run tests with release binaries
test-release: example-kmod test-kmod test-daemon-release
	sudo ../target/release/integration_test

# launch and test daemon with debug binaries
test-daemon: $(TEST_SERVICE_PATH)
	sudo systemctl start $(TEST_SERVICE)
	sleep 4  # give time to startup, TODO: remove loadbearing sleep?
	sudo ../target/debug/daemon_test
	sudo systemctl stop $(TEST_SERVICE)

# launch and test daemon with release binaries
test-daemon-release: $(TEST_SERVICE_PATH)
	sudo systemctl start $(TEST_SERVICE)
	sleep 4  # give time to startup, TODO: remove loadbearing sleep?
	sudo ../target/release/daemon_test
	sudo systemctl stop $(TEST_SERVICE)

# compile and compress 'example_kmod/hello_world_kmod.c'
example-kmod:
	@make -C kmod_example test

# remove, compile, and reinstall 'test_kmod/test_kmod.c'
# also compile 'test_kmod/test_kmod_user.c'
test-kmod:
	@make -C kmod_test test
