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

# Type definitions taken from arm-none-eabi-g++ predefines
# CXXFLAGS += -D__CHAR16_TYPE__="short unsigned int"
# CXXFLAGS += -D__CHAR32_TYPE__="long unsigned int"
# CXXFLAGS += -D__INT16_TYPE__="short int"
# CXXFLAGS += -D__INT32_TYPE__="long int"
# CXXFLAGS += -D__INT64_TYPE__="long long int"
# CXXFLAGS += -D__INT8_TYPE__="signed char"
# CXXFLAGS += -D__INTMAX_TYPE__="long long int"
# CXXFLAGS += -D__INTPTR_TYPE__="int"
# CXXFLAGS += -D__INT_FAST16_TYPE__="int"
# CXXFLAGS += -D__INT_FAST32_TYPE__="int"
# CXXFLAGS += -D__INT_FAST64_TYPE__="long long int"
# CXXFLAGS += -D__INT_FAST8_TYPE__="int"
# CXXFLAGS += -D__INT_LEAST16_TYPE__="short int"
# CXXFLAGS += -D__INT_LEAST32_TYPE__="long int"
# CXXFLAGS += -D__INT_LEAST64_TYPE__="long long int"
# CXXFLAGS += -D__INT_LEAST8_TYPE__="signed char"
# CXXFLAGS += -D__PTRDIFF_TYPE__="int"
# CXXFLAGS += -D__SIG_ATOMIC_TYPE__="int"
# CXXFLAGS += -D__SIZE_TYPE__="unsigned int"
# CXXFLAGS += -D__UINT16_TYPE__="short unsigned int"
# CXXFLAGS += -D__UINT32_TYPE__="long unsigned int"
# CXXFLAGS += -D__UINT64_TYPE__="long long unsigned int"
# CXXFLAGS += -D__UINT8_TYPE__="unsigned char"
# CXXFLAGS += -D__UINTMAX_TYPE__="long long unsigned int"
# CXXFLAGS += -D__UINTPTR_TYPE__="unsigned int"
# CXXFLAGS += -D__UINT_FAST16_TYPE__="unsigned int"
# CXXFLAGS += -D__UINT_FAST32_TYPE__="unsigned int"
# CXXFLAGS += -D__UINT_FAST64_TYPE__="long long unsigned int"
# CXXFLAGS += -D__UINT_FAST8_TYPE__="unsigned int"
# CXXFLAGS += -D__UINT_LEAST16_TYPE__="short unsigned int"
# CXXFLAGS += -D__UINT_LEAST32_TYPE__="long unsigned int"
# CXXFLAGS += -D__UINT_LEAST64_TYPE__="long long unsigned int"
# CXXFLAGS += -D__UINT_LEAST8_TYPE__="unsigned char"
# CXXFLAGS += -D__WCHAR_TYPE__="unsigned int"
# CXXFLAGS += -D__WINT_TYPE__="unsigned int"

# Common flags
COMMONFLAGS += --target=arm-none-eabi 
COMMONFLAGS += -fmessage-length=0 -fsigned-char
COMMONFLAGS += --sysroot=$(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update/arm-none-eabi

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
