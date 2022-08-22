ASM  	= avr-gcc
CC  	= avr-gcc
CXX 	= avr-g++
LD  	= avr-g++
OBJCOPY = avr-objcopy
OBJDUMP = avr-objdump
SIZE	= avr-size
QEMU	= qemu-system-avr

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

MCU ?= atmega328p
CXXFLAGS = -mmcu=${MCU} -std=c++${CXXSTD} -ffreestanding ${DEBUGFLAGS} -I ../include ${WARNINGFLAGS}
