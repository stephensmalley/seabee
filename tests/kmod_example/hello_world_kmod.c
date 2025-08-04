// SPDX-License-Identifier: Apache-2.0
/*
 * Source from https://tldp.org/LDP/lkmpg/2.6/html/x121.html
 * that will be used for testingbasic monitoring of the
 * finit_module code for kmod_monitor BPF program.
 */
#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */

static int __init hello_init(void)
{
	printk(KERN_INFO "Hello world\n");

	/*
	 * A non 0 return means init_module failed; module can't be loaded.
	 */
	return 0;
}

static void __exit hello_exit(void)
{
	printk(KERN_INFO "Goodbye world\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A simple hello world kernel module for testing");
