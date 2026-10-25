CC = zig cc
SRC = runner.c

ZIG_VER := $(shell zig version)

CFLAGS += -std=gnu23
CFLAGS += -Oz -flto -s -static
CFLAGS += -fno-unwind-tables -fmerge-all-constants
CFLAGS += -Wl,--entry=__start
CFLAGS += -s -Wl,--gc-sections,-z,norelro
CFLAGS += -Wno-int-conversion -Wno-unknown-attributes -Wno-macro-redefined
CFLAGS += -DZIG_VERSION=\"$(ZIG_VER)\"

# Architecture-specific targets, dumps, and flags
TARGET_ARM = runner_arm
DUMP_ARM = runner_arm_xxd.h
CFLAGS_ARM = -target arm-linux

TARGET_ARM64 = runner_arm64
DUMP_ARM64 = runner_arm64_xxd.h
CFLAGS_ARM64 = -target aarch64-linux

all: arm arm64

arm: $(TARGET_ARM) $(DUMP_ARM)
arm64: $(TARGET_ARM64) $(DUMP_ARM64)

$(TARGET_ARM): $(SRC)
	$(CC) $(CFLAGS) $(CFLAGS_ARM) $(SRC) -o $@
	@if command -v sstrip >/dev/null 2>&1; then sstrip $@; fi
#	@if command -v upx >/dev/null 2>&1; then upx --ultra-brute $@; fi

$(TARGET_ARM64): $(SRC)
	$(CC) $(CFLAGS) $(CFLAGS_ARM64) $(SRC) -o $@
	@if command -v sstrip >/dev/null 2>&1; then sstrip $@; fi
#	@if command -v upx >/dev/null 2>&1; then upx --ultra-brute $@; fi

$(DUMP_ARM): $(TARGET_ARM)
	xxd -i $(TARGET_ARM) > $@
	tail -n1 $@
	rm -f $(TARGET_ARM)

$(DUMP_ARM64): $(TARGET_ARM64)
	xxd -i $(TARGET_ARM64) > $@
	tail -n1 $@
	rm -f $(TARGET_ARM64)

clean:
	rm -f runner_arm runner_arm64 runner_arm_xxd.h runner_arm64_xxd.h > /dev/null 2>&1

.PHONY: all arm arm64 clean
