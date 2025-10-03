# Logging

## Log Levels

- Log Level Error: Indicates something unexpected, a problem or bug in the code
- Log Level Warn: Most commonly used when SeaBee blocks an action, correlates with security level 'blocked' in policy
- Log Level Info: Prints useful, but not security-related information to the user. Also correlates with security level 'audit' in policy.
- Log Level Debug: Primarily identifies control flow to help debug where an error happens.
- Log Level Trace: Similar to debug, but even more fine-grained. Includes labeling and kernel tracing information.

## Viewing Logs

When running SeaBee on the command line, logs will be printed the command line.

When running SeaBee as a daemon, logs will be printed to the journal.

- test logs: `sudo journalctl -u test_seabee -f`
- non-test logs: `sudo journalctl -u seabe -f`
