AS = clang-10
CC = clang-10
CXX = clang++-10
LD = clang++-10
AR = llvm-ar
OBJCOPY = $(TOOLCHAIN_BIN)/arm-none-eabi-objcopy
OBJDUMP = $(TOOLCHAIN_BIN)/arm-none-eabi-objdump
SIZE = $(TOOLCHAIN_BIN)/arm-none-eabi-size

# Manually add arm-none-eabi include folders
INCLUDES += -I$(TOOLCHAIN_ROOT)/arm-none-eabi/include
INCLUDES += -I$(TOOLCHAIN_ROOT)/arm-none-eabi/include/c++/$(TOOLCHAIN_VERSION)
INCLUDES += -I$(TOOLCHAIN_ROOT)/arm-none-eabi/include/c++/$(TOOLCHAIN_VERSION)/arm-none-eabi/thumb/v7-m/nofp
INCLUDES += -I$(TOOLCHAIN_ROOT)/arm-none-eabi/include/c++/$(TOOLCHAIN_VERSION)/backward
INCLUDES += -I$(TOOLCHAIN_ROOT)/lib/gcc/arm-none-eabi/$(TOOLCHAIN_VERSION)/include
INCLUDES += -I$(TOOLCHAIN_ROOT)/lib/gcc/arm-none-eabi/$(TOOLCHAIN_VERSION)/include-fixed

CXXFLAGS += -DARM_MATH_CM3


# Common flags
COMMONFLAGS += --target=arm-none-eabi 
COMMONFLAGS += -fmessage-length=0 -fsigned-char
COMMONFLAGS += --sysroot=$(TOOLCHAIN_ROOT)/arm-none-eabi
COMMONFLAGS += -Wno-language-extension-token
COMMONFLAGS += -Wno-gnu-include-next 

# Assembler flags
ASFLAGS += -x assembler-with-cpp

# C flags
CFLAGS += -Wno-empty-body

# C++ flags
CXXFLAGS += -Wno-deprecated-volatile

# Linker flags
LDFLAGS += --target=arm-none-eabi 
LDFLAGS += -nostdlib
LDFLAGS += -Wl,-s
LDFLAGS += -Wl,-strip-all
LDFLAGS += $(TOOLCHAIN_ROOT)/lib/gcc/arm-none-eabi/$(TOOLCHAIN_VERSION)/thumb/v7-m/nofp/crti.o
LDFLAGS += $(TOOLCHAIN_ROOT)/lib/gcc/arm-none-eabi/$(TOOLCHAIN_VERSION)/thumb/v7-m/nofp/crtbegin.o
LDFLAGS += $(TOOLCHAIN_ROOT)/lib/gcc/arm-none-eabi/$(TOOLCHAIN_VERSION)/thumb/v7-m/nofp/crtn.o
LDFLAGS += $(TOOLCHAIN_ROOT)/lib/gcc/arm-none-eabi/$(TOOLCHAIN_VERSION)/thumb/v7-m/nofp/crtend.o
LDFLAGS += -L"/usr/arm-none-eabi/lib/thumb/nofp/"
LDFLAGS += -L"/home/tobante/bin/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi/lib/thumb/v7-m/nofp/"
LDFLAGS += -lstdc++_nano -lm  -lc_nano
