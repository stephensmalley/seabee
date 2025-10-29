# Testing

## Attack Surface

The system is made up of several parts and attacks are considered against each of them.

1. Userspace process
1. eBPF programs & pins
1. eBPF maps
1. Attacks that circumvent the access control model

## Test Goals

1. Correct functionality: the system works as desired
1. Safety: the system is protected from adversaries
   * Malicious root processes
   * Other eBPF programs

## Test Filtering

If you are having trouble with a particular test and only want to run it
  or a subset of tests, then you can use a filter on the command line.

For instance, when in the `seabee` folder:

```bash
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E'
cargo test --test integration_test -- <filter>
```

Where `<filter>` is replaced by the name of the test you want to run,
  i.e. `security_kmod`.

Similarly, if you need to skip a test because it has a known failure,
  you can skip it using the `--skip <filter>` option:

```bash
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E'
cargo test --test integration_test -- --skip <filter>
```

## Test Structure

### TestSuite trait (and derivatives)

Located under `tests/src/suite.rs`

This trait has been developed to closely mimic how `pytest` fixtures work.
All tests should try to use the `TestSuite` structure when possible as it
  has the infrastructure necessary to provide shared state between tests
  via its `get_args()` function.
The exception are simple tests and tests that don't need shared state
  such as the Daemon and Fork tests.

There are currently three implementations of TestSuite:

* `seabee/tests/functional/mod.rs`
* `seabee/tests/security/mod.rs`
* `tests/src/functional/mod.rs`

### BPFState

Located under `tests/src/state/mod.rs`

`BPFState` is a generic structure that has been defined to summarize
  information gleaned from a BPF userspace including maps and pins.

The default `TestArgs` structure in `TestSuite` contains three instances of
  `BPFState`:

* Rust - Information from the perspective of a BPF file-descriptor owner
* Linux - Information from the perspective of a Linux superuser
* Ground Truth - Information provided by the test writer

The `check_args()` function in the `TestSuite` trait will check whether the
  `BPFState` was manipulated during the tests.

### Generic Functional Tests

Located under `tests/src/functional/mod.rs`

A generic functional test library has been developed under `tests/src/functional`.
Any BPF userspace can run these tests so long as they use the `BPFUserspace`
  structure defined in the `bpf` crate.
They also depend on ground truth to be defined in a TOML file, see the
  `seabee/tests/ground_truth.toml` for an example.

The following types of tests are implemented for checking correct functionality:

* Maps
  * Existence
  * Contents
* Pins
  * Existence
  * Correct directory
  * Contents
* Userspace
  * Existence

### SeaBee

Integration tests are defined in `seabee/tests/integration_tests.rs`.

#### Daemon

Daemon tests are in `seabee/tests/daemon_test.rs` and ran separately from the
  tests defined in `seabee/tests/integration_tests.rs`.

These tests verify properties specific to `systemd`.

#### Functional

Correct functionality is tested via the generic functional tests which
  is extended via a SeaBee specific TestSuite defined under
  `seabee/tests/functional/mod.rs` which includes a test to
  check that the correct inode and device id information is used within
  the `protected_pins` map.

#### Security

Safety is tested via the SeaBee security tests located under
  `seabee/tests/security/mod.rs`.
These tests verify that the userspace and associated BPF programs and maps
cannot be manipulated once the SeaBee protections are in place.
