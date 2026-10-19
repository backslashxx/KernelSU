CC = zig cc
SRC = runner.c
TARGET = runner_binary
DUMP = runner_xxd.h

CFLAGS += -target aarch64-linux -std=gnu23
CFLAGS += -Oz -flto -fno-unwind-tables -static
CFLAGS += -Wno-int-conversion -Wno-unknown-attributes -Wno-macro-redefined
CFLAGS += -s -Wl,--gc-sections,-z,norelro

all: $(TARGET) $(DUMP)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@

$(DUMP): $(TARGET)
	xxd -i $(TARGET) > $@
	rm -f $(TARGET)

clean:
	rm -f $(TARGET) > /dev/null 2>&1
	rm -f $(DUMP) > /dev/null 2>&1

.PHONY: all clean
