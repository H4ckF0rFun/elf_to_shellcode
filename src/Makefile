# make ARCH=arm PREFIX=arm-linux-gnueabi-
# make ARCH=aarch64 PREFIX=aarch64-linux-gnu-
# make ARCH=i386 PREFIX=i686-linux-gnu-
ARCH ?= amd64

ARCHS32 := arm i386
ARCHS64 := amd64 aarch64
ARCHS := $(ARCHS32) $(ARCHS64)

CC := $(PREFIX)gcc
AS := $(PREFIX)as
LD := $(PREFIX)ld

CFLAGS += -pipe -Wall -Wextra -fPIC -fomit-frame-pointer -fno-ident -fno-stack-protector -U _FORTIFY_SOURCE
LDFLAGS += -nostartfiles -nodefaultlibs -nostdlib 
LDFLAGS += -pie -e x_execve -Wl,-Bsymbolic,--no-undefined,--build-id=none
TARGET := execve

ifeq "$(filter $(ARCH),$(ARCHS))" ""
  $(error ARCH='$(ARCH)' is not supported)
endif

ifeq "$(filter $(ARCH),$(ARCHS32))" "$(ARCH)"
  CFLAGS += -DELFCLASS=ELFCLASS32
else
  CFLAGS += -DELFCLASS=ELFCLASS64
endif

ifdef DEBUG
  CFLAGS += -O0 -g
  ASFLAGS += -g
else
  CFLAGS += -fvisibility=hidden
  # Disable unwind info to make prog smaller.
  CFLAGS += -Os -fno-asynchronous-unwind-tables -fno-unwind-tables
  LDFLAGS += -s
endif

OBJS := $(patsubst %.c,%.o, $(wildcard *.c))
OBJS += $(patsubst %.S,%.o, $(wildcard $(ARCH)/*.S))

.PHONY: clean all

all: $(TARGET)

execve: $(OBJS)

clean:
	rm -rf *.o $(TARGET) */*.o

