// SPDX-License-Identifier: GPL-2.0-only
/**
 * @file lable_task.bpf.c
 */

#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "seabee_maps.h"
#include "seabee_utils.h"
#include "logging.h"

#define SIGCONT 18

/// License of the BPF program
char LICENSE[] SEC("license") = "GPL";

/// @brief Pid of the userspace process
u32 user_pid;
/// @brief the policy_id for the userspace process
u32 policy_id;
/// @brief The level of the logs to filter out
u32 log_level;

// External maps
/// @brief local storage for tasks
struct task_storage task_storage SEC(".maps");
struct log_ringbuf log_ringbuf   SEC(".maps");

/**
 * @brief Label a target process by signaling it
 *
 * @param p target process
 * @param info signal info, can also be NULL or 1
 * @param sig signal value
 * @param cred credentials of sender, may be NULL
 * @param ret the return code of the previous LSM hook
 *
 * @return {@link ALLOW} or {@link DENY}
 *
 * @see signal numbering and default actions: `man signal`
 */
SEC("lsm/task_kill")
int BPF_PROG(seabee_label_target_task, struct task_struct *p,
             struct kernel_siginfo *info, int sig, const struct cred *cred,
             int ret)
{
	if (get_pid() == user_pid && sig == SIGCONT) {
		label_task(p, p->comm, policy_id);
	}
	return ALLOW;
}
