// SPDX-License-Identifier: GPL-2.0-only
#ifndef SEABEE_UTILS_H_
#define SEABEE_UTILS_H_
/**
 * @file seabee_utils.h
 */

#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "seabee_maps.h"
#include "shared_rust_types.h"
#include "logging.h"
#include "logging_types.h"

/// An alias for the literal number 0.
#define ZERO  0
/// LSM return code for allowing an operation to continue.
#define ALLOW 0
/// LSM return code for denying an operation.
#define DENY  -1

extern struct inode_storage inode_storage;
extern struct task_storage  task_storage;
extern struct policy_map    policy_map;
extern struct map_to_pol_id map_to_pol_id;

/// return NULL for no policy id
static __always_inline u32 get_inode_pol_id(struct inode *inode)
{
	u32 *policy_id = bpf_inode_storage_get(&inode_storage, inode, 0, 0);
	if (policy_id) {
		return *policy_id;
	} else {
		return NO_POL_ID;
	}
}

/// return 0 for no policy id
static __always_inline u32 get_map_pol_id(struct bpf_map *map)
{
	struct bpf_map_data *data = bpf_map_lookup_elem(&map_to_pol_id, &map);
	if (data) {
		return data->policy_id;
	} else {
		return NO_POL_ID;
	}
}

/**
 * @brief gets the pid for the current context
 */
static __always_inline u32 get_pid()
{
	// we use tgid instead of pid because tgid == pid in userspace.
	// we want to protect all threads in our thread group (process)
	return bpf_get_current_pid_tgid() >> 32;
}

/**
 * @brief gets the task for the current context
 */
struct task_struct *get_task()
{
	return bpf_get_current_task_btf();
}

/**
 * @brief get the policy_config for a policy id
 *
 * @param policy_id target policy id
 *
 * @return a policy config associated with the policy_id or NULL if
 * none was found.
 */
static __always_inline struct c_policy_config *get_policy_config(u32 policy_id)
{
	if (policy_id == NO_POL_ID) {
		return NULL;
	}
	return bpf_map_lookup_elem(&policy_map, &policy_id);
}

/**
 * @brief checks if there is a valid policy configuration for the policy id
 *
 * @param policy_id target policy id
 *
 * @return true if the policy id has a valid config, false otherwise
 */
static __always_inline bool is_valid_policy_id(u32 policy_id)
{
	return get_policy_config(policy_id) != NULL;
}

/**
 * @brief gets the data associated with a particular task
 *
 * @param t target task
 *
 * @return the seabee_task_data for the target task or NULL if task is not
 * tracked by seabee
 */
static __always_inline struct seabee_task_data *
get_target_task_data(struct task_struct *t)
{
	return bpf_task_storage_get(&task_storage, t, 0, 0);
}

/**
 * @brief gets the data associated with current task
 *
 * @return the seabee_task_data for current task or NULL if task is not
 * tracked by seabee
 */
static __always_inline struct seabee_task_data *get_task_data()
{
	struct task_struct *task = get_task();
	return get_target_task_data(task);
}

/**
 * @brief gets the policy id for a target task
 *
 * @param t the target task
 * @return the policy id for the task or NO_POL_ID
 */
static __always_inline u32 get_target_task_pol_id(struct task_struct *t)
{
	struct seabee_task_data *data = get_target_task_data(t);
	if (data) {
		return data->pol_id;
	} else {
		return NO_POL_ID;
	}
}

/**
 * @brief gets the policy id for a task
 *
 * @return the policy id for the task or NO_POL_ID
 */
static __always_inline u32 get_task_pol_id()
{
	struct seabee_task_data *data = get_task_data();
	if (data) {
		return data->pol_id;
	} else {
		return NO_POL_ID;
	}
}

/**
 * @brief Checks if this task is associataed with a SeaBee policy id.
 * If so, set a flag that determines whether or not the current task is
 * executing BPF_OBJ_PIN
 *
 * @param b a u32 that will be the new flag. 0 for false. 1 for true.
 */
static __always_inline void set_task_pinning(u32 flag)
{
	struct task_struct      *task = get_task();
	struct seabee_task_data *data =
		bpf_task_storage_get(&task_storage, task, 0, 0);
	if (data && data->pol_id != NO_POL_ID) {
		// set flag if it has changed
		if (data->is_pinning != flag) {
			data->is_pinning = flag;
			u64 log[3]       = { (u64)task->comm, (u64)task->tgid, (u64)flag };
			log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
			                "set task %s(%d) pinning to %lu", log, sizeof(log));
		}
	}
}

enum object_type {
	OBJECT_TYPE_INODE,
	OBJECT_TYPE_TASK,
	OBJECT_TYPE_MAP,
};

/**
 * @brief gets the policy id for an object only if it has a valid policy associated with it.
 *
 * @param object a pointer to the object we want a label for
 * @param object_type identifies what type of pointer the object is
 *
 * @return policy_id for an object or NO_POL_ID
*/
static __always_inline u32 get_object_valid_policy_id(void            *object,
                                                      enum object_type type)
{
	// get current label
	u32 current_pol_id = NO_POL_ID;
	switch (type) {
	case OBJECT_TYPE_TASK:
		current_pol_id = get_target_task_pol_id((struct task_struct *)object);
		break;
	case OBJECT_TYPE_INODE:
		current_pol_id = get_inode_pol_id((struct inode *)object);
		break;
	case OBJECT_TYPE_MAP:
		current_pol_id = get_map_pol_id((struct bpf_map *)object);
		break;
	}
	// check if label has a policy
	if (is_valid_policy_id(current_pol_id)) {
		return current_pol_id;
	}
	//TODO: should we find a way to reset of the policy ID to zero if there is no policy?
	return NO_POL_ID;
}

/**
 * @brief label a task with a policy id
 *
 * @param task the task to label
 * @param policy_id the label for the task
 */
static __always_inline void label_task(struct task_struct  *task,
                                       const unsigned char *task_name,
                                       u32                  policy_id)
{
	u32 current_pol_id = get_object_valid_policy_id(task, OBJECT_TYPE_TASK);
	if (current_pol_id == policy_id) {
		// Already correctly labled
		return;
	} else if (!is_valid_policy_id(policy_id)) {
		// Don't propogate invalid policy ids
		u64 log[3] = {
			(u64)task_name,
			(u64)task->tgid,
			(u64)policy_id,
		};
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "Did not label task %s(%d) since %d is invalid", log,
		                sizeof(log));
	} else if (current_pol_id != NO_POL_ID) {
		// Already labled with differnt label
		u64 log[4] = { (u64)task_name, (u64)task->tgid, (u64)policy_id,
			           (u64)current_pol_id };
		log_generic_msg(
			LOG_LEVEL_ERROR, LOG_REASON_ERROR,
			"failed to label task %s(%d) as %d. Task already belongs to policy %d",
			log, sizeof(log));
	} else {
		// Label with new policy id
		struct seabee_task_data  new_data      = { policy_id, 0 };
		struct seabee_task_data *new_data_blob = bpf_task_storage_get(
			&task_storage, task, &new_data, BPF_LOCAL_STORAGE_GET_F_CREATE);
		u64 log[3] = { (u64)task_name, (u64)task->tgid, (u64)policy_id };
		if (new_data_blob) {
			log_generic_msg(LOG_LEVEL_DEBUG, LOG_REASON_DEBUG,
			                "label task %s(%d) as %d", log, sizeof(log));
		} else {
			log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
			                "failed to label task %s(%d) as %d", log,
			                sizeof(log));
		}
	}
}

/**
 * @brief label an inode with a policy id
 *
 * @param dentry the dentry associated with the inode
 * @param inode the inode to label
 * @param policy_id the label to use
 */
static __always_inline void label_inode(struct dentry *dentry,
                                        struct inode *inode, u32 policy_id)
{
	const unsigned char *name = dentry->d_name.name;
	u32 current_pol_id = get_object_valid_policy_id(inode, OBJECT_TYPE_INODE);
	if (current_pol_id == policy_id) {
		// Already correctly labled
		return;
	} else if (!is_valid_policy_id(policy_id)) {
		// Don't propogate invalid policy ids
		u64 log[3] = { (u64)name, (u64)policy_id };
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "Did not label inode %s since %d is invalid", log,
		                sizeof(log));
	} else if (current_pol_id != NO_POL_ID) {
		// Has a differnt policy id already
		u64 log[3] = { (u64)name, (u64)policy_id, (u64)current_pol_id };
		log_generic_msg(
			LOG_LEVEL_ERROR, LOG_REASON_ERROR,
			"failed to label inode for %s as %d. Inode already belongs to policy %d",
			log, sizeof(log));
	} else {
		// Assign new inode policy id
		u32 *label  = bpf_inode_storage_get(&inode_storage, inode, &policy_id,
		                                    BPF_LOCAL_STORAGE_GET_F_CREATE);
		u64  log[2] = { (u64)name, (u64)policy_id };
		if (label) {
			log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
			                "label inode for '%s' as %d", log, sizeof(log));
		} else {
			log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
			                "failed to label inode for %s as %d", log,
			                sizeof(log));
		}
	}
}

/**
 * @brief label a map a with a policy id.
 *
 * @param map the map to label
 * @param policy_id the id for the map
 *
 * @return will return ALLOW
 */
static __always_inline int label_map_with_id(struct bpf_map *map, u32 policy_id)
{
	// unsure if map can be null, but this made the verifier happy
	if (!map) {
		return ALLOW;
	}

	struct bpf_map_data map_data;
	map_data.policy_id = policy_id;
	BPF_CORE_READ_STR_INTO(&map_data.name, map, name);

	// NOEXIST ensures that we cannot overwrite an existing map label
	long err =
		bpf_map_update_elem(&map_to_pol_id, &map, &map_data, BPF_NOEXIST);
	u64 data[3] = { (u64)map_data.name, (u64)BPF_CORE_READ(map, id),
		            (u64)policy_id };
	if (err < 0) {
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: update elem failed map %s(%d) for policy %d",
		                data, sizeof(data));
	} else {
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG,
		                "label map %s(%d) as %d", data, sizeof(data));
	}
	return ALLOW;
}

/**
 * @brief label a map automatically based the policy id of the current task.
 *
 * The label will be NO_POL_ID if task has no policy id associated with it.
 *
 * @param map the map to label
 *
 * @return will return ALLOW
 */
static __always_inline int label_map(struct bpf_map *map)
{
	return label_map_with_id(map, get_task_pol_id());
}

static __always_inline int unlabel_map(struct bpf_map *map)
{
	// unsure if map can be null, but this made the verifier happy
	if (!map) {
		return ALLOW;
	}

	// exit early if map is not tracked
	u32 *policy_id = bpf_map_lookup_elem(&map_to_pol_id, &map);
	if (!policy_id) {
		return ALLOW;
	}

	// delete map
	s32  err = bpf_map_delete_elem(&map_to_pol_id, &map);
	char map_name[BPF_MAP_NAME_LEN];
	BPF_CORE_READ_STR_INTO(&map_name, map, name);
	u64 data[] = { (u64)map_name, (u64)BPF_CORE_READ(map, id) };
	if (err < 0) {
		log_generic_msg(LOG_LEVEL_ERROR, LOG_REASON_ERROR,
		                "Error: failed to unlabel map: %s(%d)", data,
		                sizeof(data));
	} else {
		log_generic_msg(LOG_LEVEL_TRACE, LOG_REASON_DEBUG, "unlabel map %s(%d)",
		                data, sizeof(data));
	}
	return ALLOW;
}

#endif // SEABEE_UTILS_H_
