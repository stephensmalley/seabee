KMOD_DIR = /lib/modules/$(shell uname -r)
INSTALL_MOD_DIR = extra
KMOD_BUILD = $(KMOD_DIR)/build
KMOD_PATH = $(KMOD_DIR)/$(INSTALL_MOD_DIR)/test_kmod.ko

KMOD_USER = test_kmod_user

obj-m += test_kmod.o

.PHONY: clean test show

clean:
	sudo make -C $(KMOD_BUILD) M=$$PWD clean
	sudo rm -f $(KMOD_PATH) $(KMOD_USER)

$(KMOD_USER): test_kmod_user.c test_kmod.h
	@gcc test_kmod_user.c -o test_kmod_user

$(KMOD_PATH): test_kmod.c test_kmod.h
	@sudo make -C $(KMOD_BUILD) M=$$PWD modules
	@sudo make -C $(KMOD_BUILD) M=$$PWD modules_install INSTALL_MOD_DIR=$(INSTALL_MOD_DIR)
	@sudo depmod

show:
	lsmod

test: $(KMOD_PATH) $(KMOD_USER)
	@-sudo modprobe -rq test_kmod
	@sudo modprobe test_kmod
