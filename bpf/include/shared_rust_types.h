// SPDX-License-Identifier: Apache-2.0
#ifndef SHARED_RUST_TYPES_H_
#define SHARED_RUST_TYPES_H_
/**
 * @file logging_types.h
 *
 * shared types for which rust bindings are generated
 */
#include "constants.h"

/**
 * @brief Specify what amount of action to take
 *
 * @todo update logging to use this system
 */
enum SecurityLevel {
	SECURITY_UNINIT = 0, // uninitialized
	SECURITY_ALLOW,      // allow an action
	SECURITY_AUDIT,      // allow an action and audit it
	SECURITY_BLOCK,      // deny action and audit it
};

/**
 * @brief  c_policy_config contains security levels for protected objects and
 * corresponds to a policy id.
 *
 * each of the fields in this struct corresponds to an 'enum SecurityLevel'
 * but is not shown as such since enums within structs are not supported
 * by the rust bindings we generate based on this code.
 */
struct c_policy_config {
	unsigned long long signal_allow_mask; // 8
	unsigned char      signal_access;     // 1
	unsigned char      ptrace_access;     // 1
	unsigned char      file_write_access; // 1
	unsigned char      map_access;        // 1
	unsigned char      protect_pins;      // 1
	unsigned char      padding_1;         // 3
	unsigned char      padding_2;
	unsigned char      padding_3;
};

#endif
