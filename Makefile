ifndef KP_DIR
    KP_DIR = ../..
endif

# Android NDK support
ifdef ANDROID_NDK
    NDK_BIN = $(ANDROID_NDK)/toolchains/llvm/prebuilt/darwin-x86_64/bin
    CC = $(NDK_BIN)/aarch64-linux-android21-clang
    LD = $(NDK_BIN)/ld.lld
else ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
else
    CC = $(TARGET_COMPILE)gcc
    LD = $(TARGET_COMPILE)ld
endif

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

KPM_CFLAGS := -fno-pic -fno-PIC \
	-fno-stack-protector \
	-fno-asynchronous-unwind-tables -fno-unwind-tables

objs := xpida.o

all: xpida.kpm xpida_cli

xpida.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(KPM_CFLAGS) $(INCLUDE_FLAGS) -Txpida.lds -c -O2 -o $@ $<

CLI_CFLAGS := -I$(KP_DIR)/kernel/patch/include -O2 -static

xpida_cli: xpida_cli.c
	${CC} $(CLI_CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm xpida_cli
	find . -name "*.o" | xargs rm -f