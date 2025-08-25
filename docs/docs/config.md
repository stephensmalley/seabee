# SeaBee Configuration

This documentation is still being developed.

SeaBee has various configuration options and various ways to apply them.

All the configuration code can be viewed in `seabee/src/config.rs` and `seabee/src/cli.rs`.

Configuration cannot be updated while SeaBee is running.

## Default Configuration

If no custom configuration is applied, SeaBee will use its default configuration, specified at `seabee/src/cli.rs`

The default configuration is a secure way to use SeaBee.

## Notable Configuration Options

`--sigint` allows you to kill SeaBee with signal 2 or `SIGINT` or ctrl+C, very useful for debugging

`--verify-policies` ensures policy updates are verified, prevents unauthorized policy updates,
essential for security.

`--verify-keys` false by default, true means every key file added to SeaBee must be signed by the root key.
This effectively means the controller of the root key must authorize every other key that is used by SeaBee.

## Configuration via the Command Line

`seabee --help` explains all of the possible configuration options.

## Configuration via a File

at startup, SeaBee pulls configuration information from `/etc/seabee/config.yaml`

For conveinance, this file can be updated while SeaBee is turned off via `seabeectl config`

This file can accept all of the same key-value pairs as the command line.
See `tests/configs` for some example configuraiton files

## Specifying Configuration in Multiple Places

Any option not specified will remain as the default.

If the same option is specified in a file and on the command line, the command line takes precedence.
