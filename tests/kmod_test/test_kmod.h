// SPDX-License-Identifier: Apache-2.0
#ifndef AUTOLOAD_KMOD_H_
#define AUTOLOAD_KMOD_H_

#define NETLINK_USER 30

// Kernel module commands
char *CMD_TEST           = "TEST";           // Test kmod send/receive
char *CMD_REQUEST_MODULE = "REQUEST MODULE"; // Try to call `request_module`

// Kernel module responses
char *RESPONSE_OK          = "OK";     // Action succeeded
char *RESPONSE_DENIED      = "DENIED"; // Action was not allowed
char *RESPONSE_ERROR       = "ERROR";  // Action failed on a different error
char *RESPONSE_CMD_UNKNOWN = "CMD UNKNOWN"; // Command was not recognized

#endif // AUTOLOAD_KMOD_H_
