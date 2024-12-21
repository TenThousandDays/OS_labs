#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Solar");
MODULE_DESCRIPTION("Simple Linux kernel module");
MODULE_VERSION("v0.01");

static int __init mod_init(void){
	printk(KERN_INFO "Welcome to the Tomsk State University!\n");
	return 0;
}

static void __exit mod_exit(void){
	printk(KERN_INFO "Tomsk State University forever!\n");
}

module_init(mod_init);
module_exit(mod_exit);
