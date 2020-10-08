# TOOLCHAIN_ROOT ?= $(HOME)/bin/gcc-arm-none-eabi-9-2020-q2-update
# TOOLCHAIN_ROOT ?= /work/gcc-arm-none-eabi-9-2020-q2-update
TOOLCHAIN_ROOT ?= $(shell which arm-none-eabi-gcc | sed 's/\/bin\/arm-none-eabi-gcc//g')
TOOLCHAIN_BIN ?= $(TOOLCHAIN_ROOT)/bin
TOOLCHAIN_VERSION := $(strip $(shell $(TOOLCHAIN_ROOT)/bin/arm-none-eabi-g++ --version | head -n 1 | grep -Po '\d+\.\d+\.\d+'))

DEFINES += -DSTM32F103xB

INCLUDES += -I../../..
INCLUDES += -Iinclude
INCLUDES += -Iinclude/CMSIS/Include 
INCLUDES += -Iinclude/CMSIS/Device/ST/STM32F1xx/Include 

ARCH += -mcpu=cortex-m3
ARCH += -mthumb
ARCH += -mfloat-abi=soft

COMMONFLAGS += $(ARCH)
COMMONFLAGS += -flto
COMMONFLAGS += -ffreestanding
COMMONFLAGS += -fno-unroll-loops
COMMONFLAGS += -fomit-frame-pointer
COMMONFLAGS += -ffunction-sections 
COMMONFLAGS += -fdata-sections
COMMONFLAGS += -Werror
COMMONFLAGS += -Wall
COMMONFLAGS += -Wextra
COMMONFLAGS += -Wpedantic

ifndef DEBUG
	COMMONFLAGS += -Os
	DEFINES += -DNDEBUG
else
	COMMONFLAGS += -Og
	COMMONFLAGS += -g3
	COMMONFLAGS += -ggdb
endif 


CFLAGS += $(COMMONFLAGS)
CFLAGS += -std=gnu11
CFLAGS += -MMD -MP
CFLAGS += -Wno-int-to-pointer-cast
CFLAGS += -Wno-unused-parameter 
CFLAGS += -Wno-switch-default

CXXFLAGS += $(COMMONFLAGS)
CXXFLAGS += -std=gnu++2a
CXXFLAGS += -fpermissive
CXXFLAGS += -fno-rtti
CXXFLAGS += -fno-exceptions
CXXFLAGS += -fno-use-cxa-atexit
CXXFLAGS += -fno-threadsafe-statics
CXXFLAGS += -ftemplate-backtrace-limit=0

LDSCRIPT = STM32F103C8TX_FLASH.ld
LDFLAGS += -T$(LDSCRIPT) 
LDFLAGS += $(COMMONFLAGS)
LDFLAGS += -Wl,-Map="$(BIN).map"
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -static 


