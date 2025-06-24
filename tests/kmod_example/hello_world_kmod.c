// SPDX-License-Identifier: Apache-2.0
/*
 * Source from https://tldp.org/LDP/lkmpg/2.6/html/x121.html
 * that will be used for testingbasic monitoring of the
 * finit_module code for kmod_monitor BPF program.
 */
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */

int init_module(void)
{
	printk(KERN_INFO "Hello world 1.\n");

	/*
	 * A non 0 return means init_module failed; module can't be loaded.
	 */
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Goodbye world 1.\n");
}

MODULE_LICENSE("GPL");
