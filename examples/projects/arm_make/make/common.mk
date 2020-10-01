ARCH += -mcpu=cortex-m3
ARCH += -mthumb
ARCH += -mfloat-abi=soft

COMMONFLAGS += $(ARCH)
COMMONFLAGS += -flto
COMMONFLAGS += -Os
# COMMONFLAGS += -Og
# COMMONFLAGS += -g3
# COMMONFLAGS += -ggdb
COMMONFLAGS += -ffreestanding
COMMONFLAGS += -fno-unroll-loops
COMMONFLAGS += -fomit-frame-pointer
COMMONFLAGS += -ffunction-sections 
COMMONFLAGS += -fdata-sections
COMMONFLAGS += -Werror
COMMONFLAGS += -Wall
COMMONFLAGS += -Wextra
COMMONFLAGS += -Wpedantic

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
# LDFLAGS += -flto 
# LDFLAGS += -Wl,--start-group
# LDFLAGS += -lc
# LDFLAGS += -lm
# LDFLAGS += -Wl,--end-group


DEFINES += -DSTM32F103xB
# DEFINES += -DUSE_HAL_DRIVER 
DEFINES += -DNDEBUG

INCLUDES += -I../../..
INCLUDES += -Iinclude
INCLUDES += -Iinclude/CMSIS/Include 
INCLUDES += -Iinclude/CMSIS/Device/ST/STM32F1xx/Include 
