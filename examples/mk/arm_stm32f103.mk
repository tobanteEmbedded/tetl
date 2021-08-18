TOOLCHAIN 	= arm-none-eabi-
TOOLCHAIN_ROOT ?= $(shell which arm-none-eabi-gcc | sed 's/\/bin\/arm-none-eabi-gcc//g')
TOOLCHAIN_BIN ?= $(TOOLCHAIN_ROOT)/bin
TOOLCHAIN_VERSION := $(strip $(shell $(TOOLCHAIN_ROOT)/bin/arm-none-eabi-g++ --version | head -n 1 | grep -Po '\d+\.\d+\.\d+'))


AS 			= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)gcc
CC 			= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)gcc
CXX 		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)g++
LD  		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)g++
OBJCOPY		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)objcopy
OBJDUMP		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)objdump
SIZE		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)size


DEFINES += -DSTM32F103xB

INCLUDES += -I../

ifdef DEBUG
DEBUGFLAGS = -Og -g
else
DEBUGFLAGS = -Os -DNDEBUG=1
endif

ARCH += -mcpu=cortex-m3
ARCH += -mthumb
ARCH += -mfloat-abi=soft

COMMONFLAGS += $(ARCH)
COMMONFLAGS += $(DEBUGFLAGS)
COMMONFLAGS += -ffreestanding
COMMONFLAGS += -fno-unroll-loops
COMMONFLAGS += -fomit-frame-pointer
COMMONFLAGS += -ffunction-sections
COMMONFLAGS += -fdata-sections

WARNINGFLAGS  = -Wall -Wextra -Wpedantic -Werror
WARNINGFLAGS += -Wstrict-aliasing
WARNINGFLAGS += -Wshadow
WARNINGFLAGS += -Wunused-parameter
WARNINGFLAGS += -Wnarrowing
WARNINGFLAGS += -Wreorder
WARNINGFLAGS += -Wsign-compare
WARNINGFLAGS += -Wswitch-enum
WARNINGFLAGS += -Wmisleading-indentation
WARNINGFLAGS += -Wlogical-op
WARNINGFLAGS += -Wduplicated-branches
WARNINGFLAGS += -Wduplicated-cond
# WARNINGFLAGS += -Wsign-conversion

COMMONFLAGS += ${WARNINGFLAGS}

CFLAGS += $(COMMONFLAGS)
CFLAGS += -std=c11
CFLAGS += -MMD -MP
CFLAGS += -Wno-int-to-pointer-cast
CFLAGS += -Wno-unused-parameter
CFLAGS += -Wno-switch-default

CXXFLAGS += $(COMMONFLAGS)
CXXFLAGS += -std=c++${CXXSTD}
CXXFLAGS += -fpermissive
CXXFLAGS += -fno-rtti
CXXFLAGS += -fno-exceptions
CXXFLAGS += -fno-use-cxa-atexit
CXXFLAGS += -fno-threadsafe-statics
CXXFLAGS += -ftemplate-backtrace-limit=0
CXXFLAGS += $(INCLUDES)

