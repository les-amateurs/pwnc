#include <linux/module.h>

#define KMAGIC 0xffffffff13371337

static int __init stop_init(void) {
    ((void(*)(void))KMAGIC)();
    return 0;
}
module_init(stop_init);

static void __exit stop_exit(void) {}
module_exit(stop_exit);

MODULE_LICENSE("something");