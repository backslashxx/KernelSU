# NOTE: unity build. single unit.

obj-$(CONFIG_KSU) := ksu.o

CFLAGS_ksu.o += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
CFLAGS_ksu.o += -I$(objtree)/security/selinux

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))

# MINIMAL_SUPPORTED_KERNEL
CFLAGS_ksu.o += -DKSU_VERSION=32377

ifndef KSU_EXPECTED_SIZE
KSU_EXPECTED_SIZE := 0x033b
endif

ifndef KSU_EXPECTED_HASH
KSU_EXPECTED_HASH := c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6
endif

ifdef KSU_MANAGER_PACKAGE
CFLAGS_ksu.o += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
$(info -- KernelSU Manager package name: $(KSU_MANAGER_PACKAGE))
endif

$(info -- KernelSU Manager signature size: $(KSU_EXPECTED_SIZE))
$(info -- KernelSU Manager signature hash: $(KSU_EXPECTED_HASH))

CFLAGS_ksu.o += -DEXPECTED_SIZE=$(KSU_EXPECTED_SIZE)
CFLAGS_ksu.o += -DEXPECTED_HASH=\"$(KSU_EXPECTED_HASH)\"

ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
CFLAGS_ksu.o += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
CFLAGS_ksu.o += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

ifeq ($(shell grep -q "^DEFINE_RWLOCK(policy_rwlock);" $(srctree)/security/selinux/ss/services.c; echo $$?),0)
$(info -- KernelSU/compat: exported policy_rwlock found!)
CFLAGS_ksu.o += -DKSU_COMPAT_HAS_EXPORTED_POLICY_RWLOCK
endif

CFLAGS_ksu.o += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-missing-prototypes
CFLAGS_ksu.o += -Wno-declaration-after-statement -Wno-unused-function -Wno-format -Wno-incompatible-pointer-types
CFLAGS_ksu.o += -Wno-unused-variable -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
CFLAGS_ksu.o += -Wno-macro-redefined

# so we can see stack use atleast, as we disable all stack safety here
CFLAGS_ksu.o += $(call cc-option, -Wframe-larger-than=1024)

# to make sure we can use builtins
CFLAGS_REMOVE_ksu.o += -fno-builtin

ifneq ($(CONFIG_KSU_DEBUG),y)
# strip, remove tracing / profiling
# comment out if proper backtrace is needed
CFLAGS_ksu.o += -g0 -fno-unwind-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer
CFLAGS_REMOVE_ksu.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_ksu.o += -pg

# if cflags can be macro'd, this will be called 'TRUST_ME'
CFLAGS_ksu.o += -fno-stack-protector -fno-stack-check
CFLAGS_REMOVE_ksu.o += -fsanitize=shadow-call-stack
endif # CONFIG_KSU_DEBUG

# Keep a new line here!! Because someone may append config
