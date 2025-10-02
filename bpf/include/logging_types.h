// SPDX-License-Identifier: Apache-2.0
#ifndef LOGGING_TYPES_H_
#define LOGGING_TYPES_H_
/**
 * @file logging_types.h
 */

// Bindgen throws a lot of include errors with vmlinux.h
// Therefore, type declarations are pulled from here into logging.h

#include "constants.h"

/**
 * @brief Standard log levels indicating the severity of the message.
 *
 * LOG_LEVEL_ERROR will always be printed out whereas LOG_LEVEL_TRACE
 * has the lowest priority. The logging system will only submit logs
 * at or above the level specified in the log_level defined
 * the seabee.bpf.c file.
 */
enum LogLevel {
	LOG_LEVEL_OFF   = 0,
	LOG_LEVEL_ERROR = 1,
	LOG_LEVEL_WARN  = 2,
	LOG_LEVEL_INFO  = 3,
	LOG_LEVEL_DEBUG = 4,
	LOG_LEVEL_TRACE = 5,
};

/**
 * @brief Standard reasons as to why a log is being output.
 *
 * This is separate from log level and gives additional context that
 * a program can choose depending on what action is being performed.
 */
enum LogReason {
	LOG_REASON_UNKNOWN = 0,
	LOG_REASON_ALLOW,
	LOG_REASON_AUDIT,
	LOG_REASON_DENY,
	LOG_REASON_DEBUG,
	LOG_REASON_ERROR,
};

/**
 * @brief The link between a program's log structure and the logging system.
 *
 * Each program's log struct will be named here and referred to in
 * the log_hdr structure to give the logging system an idea as to what
 * C binding structure to use when decoding the bytes from the ringbuf.
 */
enum EventType {
	EVENT_TYPE_UNKNOWN = 0,
	EVENT_TYPE_MSG,
	EVENT_TYPE_INODE_ACCESS,
	EVENT_TYPE_SB_UMOUNT,
	EVENT_TYPE_BPF_MAP,
	EVENT_TYPE_TASK_KILL,
	EVENT_TYPE_KERNEL_MODULE_REQUEST,
	EVENT_TYPE_KERNEL_READ_FILE,
	EVENT_TYPE_KERNEL_LOAD_DATA,
	EVENT_TYPE_PTRACE_ACCESS_CHECK,
	EVENT_TYPE_BPF_WRITE_USER,
	EVENT_TYPE_TASK_ALLOC,
	// we cannot remove this log type because the file access
	// permissions are different from the inode permissions
	EVENT_TYPE_FILE_OPEN,
	EVENT_TYPE_UNIX_STREAM_CONNECT,
};

/**
 * @brief  Header attached to every log message.
 *
 * Provides standard identifying information about a log in order
 * to assist in decoding as well as filtering (log level).
 */
struct log_hdr {
	/// @brief alias for {@link LogLevel}
	unsigned char  level;
	/// @brief alias for {@link LogReason}
	unsigned char  reason;
	/// @brief alias for {@link EventType}
	unsigned short type;
	/// @brief process id that is triggering the hook
	unsigned long  pid;
	/// @brief thread id that is triggering the hook
	unsigned long  tid;
	/// @brief effective user id of the process
	unsigned long  uid;
	/// @brief policy id for this object
	unsigned long  pol_id;
	/// @brief same as /proc/{pid}/comm
	unsigned char  comm[COMM_LEN];
};

/// @brief Generic log with a message field
struct generic_msg_log {
	/// @brief standard log header
	struct log_hdr header;
	/// @brief a 128 character message
	unsigned char  msg[MAX_STR_LEN];
};

/// @brief Log a sb_umount() syscall
struct sb_umount_log {
	/// @brief standard log header
	struct log_hdr header;
	/// @brief device number of the superblock being unmounted
	unsigned long  target_dev;
};

/// @brief Log for a eBPF map access via a bpf() syscall
struct bpf_map_log {
	/// @brief standard log header
	struct log_hdr header;
	/// @brief the name of the map
	unsigned char  name[MAX_STR_LEN];
	/// @brief id number of eBPF map being accessed
	unsigned int   map_id;
};

/// @brief Log a task_kill() LSM hook event
struct task_kill_log {
	/// @brief standard log header
	struct log_hdr header;
	/// @brief same as /proc/{pid}/comm
	unsigned char  target_comm[COMM_LEN];
	/// @brief process id of the PID receiving the signal
	int            target_pid;
	/// @brief id of the signal being sent
	int            signum;
};

/// @brief Log for a kernel_module_request() LSM hook event
struct kernel_module_request_log {
	/// @brief standard log header
	struct log_hdr header;
	/// @brief the name of the kernel module being requested to load
	unsigned char  kmod_name[MODULE_NAME_LEN];
};

/// @brief Log for a kernel_read_file() LSM hook event
struct kernel_read_file_log {
	/// @brief standard log header
	struct log_hdr header;
	/// @brief the type of data being loaded into the kernel
	/// @todo Copy and use `enum kernel_read_file_id` from `vmlinux.h`
	unsigned int   id;
	/// @brief the name of the file being loaded
	unsigned char  filename[MAX_STR_LEN];
};

/// @brief Log for a kernel_load_data() LSM hook event
struct kernel_load_data_log {
	/// @brief standard log header
	struct log_hdr header;
	/// @brief the type of data being loaded into the kernel
	/// @todo Copy and use `enum kernel_read_file_id` from `vmlinux.h`
	unsigned int   id;
};

/// @brief Log for a ptrace_access_check() LSM hook event
struct ptrace_access_check_log {
	/// @brief standard log header
	struct log_hdr header;
	/// @brief The process ID to be traced
	int            target_pid;
	/// @brief The ptrace mode used
	unsigned int   mode;
	/// @brief same as /proc/{pid}/comm for traced process
	unsigned char  target_comm[COMM_LEN];
};

/// @brief Log for various events that access inodes (file_open, inode_unlink)
struct inode_access_log {
	/// @brief standard log header
	struct log_hdr header;
	/// @brief the first 128 characters of file name
	unsigned char  name[MAX_STR_LEN];
};

#endif // LOGGING_TYPES_H_
