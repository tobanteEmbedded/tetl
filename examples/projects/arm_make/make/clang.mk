AS = clang-10
CC = clang-10
CXX = clang++-10
LD = clang++-10
AR = llvm-ar
OBJCOPY = arm-none-eabi-objcopy
OBJDUMP = arm-none-eabi-objdump
SIZE = arm-none-eabi-size

# Manually add arm-none-eabi include folders
INCLUDES += -I$(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi/include
INCLUDES += -I$(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi/include/c++/9.3.1
INCLUDES += -I$(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi/include/c++/9.3.1/arm-none-eabi/thumb/v7-m/nofp
INCLUDES += -I$(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi/include/c++/9.3.1/backward
INCLUDES += -I$(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/lib/gcc/arm-none-eabi/9.3.1/include
INCLUDES += -I$(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/lib/gcc/arm-none-eabi/9.3.1/include-fixed

CXXFLAGS += -DARM_MATH_CM3


# Common flags
COMMONFLAGS += --target=arm-none-eabi 
COMMONFLAGS += -fmessage-length=0 -fsigned-char
COMMONFLAGS += --sysroot=$(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi
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
LDFLAGS += $(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/lib/gcc/arm-none-eabi/9.3.1/thumb/v7-m/nofp/crti.o
LDFLAGS += $(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/lib/gcc/arm-none-eabi/9.3.1/thumb/v7-m/nofp/crtbegin.o
LDFLAGS += $(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/lib/gcc/arm-none-eabi/9.3.1/thumb/v7-m/nofp/crtn.o
LDFLAGS += $(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/lib/gcc/arm-none-eabi/9.3.1/thumb/v7-m/nofp/crtend.o
LDFLAGS += -L"/usr/arm-none-eabi/lib/thumb/nofp/"
LDFLAGS += -L"/home/tobante/bin/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi/lib/thumb/v7-m/nofp/"
LDFLAGS += -lstdc++_nano -lm  -lc_nano
