TOOLCHAIN 		 = msp430-elf-
TOOLCHAIN_ROOT 	?= $(shell which msp430-elf-gcc | sed 's/\/bin\/msp430-elf-gcc//g')
TOOLCHAIN_BIN 	?= $(TOOLCHAIN_ROOT)/bin

AS 			= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)gcc
CC 			= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)gcc
CXX 		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)g++
LD  		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)g++
OBJCOPY		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)objcopy
OBJDUMP		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)objdump
SIZE		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)size

ifdef DEBUG
DEBUGFLAGS = -Og -g
else
DEBUGFLAGS = -Os -flto
endif

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

MCU ?= msp430fr5969
CXXFLAGS = -mmcu=${MCU} -std=c++${CXXSTD} ${DEBUGFLAGS} -I../ ${WARNINGFLAGS}