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

TARGET_ARM64 = runner_binary_aarch64
DUMP_ARM64   = runner_xxd_aarch64.h

TARGET_ARM = runner_binary_arm
DUMP_ARM   = runner_xxd_arm.h

all: $(DUMP_ARM64) $(DUMP_ARM)

$(TARGET_ARM64): $(SRC)
	$(CC) $(CFLAGS) -target aarch64-linux $(SRC) -o $@

$(DUMP_ARM64): $(TARGET_ARM64)
	xxd -i $(TARGET_ARM64) > $@
	tail -n1 $@
	rm -f $(TARGET_ARM64)

$(TARGET_ARM): $(SRC)
	$(CC) $(CFLAGS) -target arm-linux $(SRC) -o $@

$(DUMP_ARM): $(TARGET_ARM)
	xxd -i $(TARGET_ARM) > $@
	tail -n1 $@
	rm -f $(TARGET_ARM)

clean:
	rm -f runner_binary_* runner_xxd_*.h > /dev/null 2>&1

.PHONY: all clean
