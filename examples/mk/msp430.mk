CPATH = /c/bin/msp430-gcc-9.3.1.11_win64/msp430-gcc-9.3.1.11_win64/bin

ASM  	= ${CPATH}/msp430-elf-gcc
CC  	= ${CPATH}/msp430-elf-gcc
CXX 	= ${CPATH}/msp430-elf-g++
LD  	= ${CPATH}/msp430-elf-g++
OBJCOPY = ${CPATH}/msp430-elf-objcopy
OBJDUMP = ${CPATH}/msp430-elf-objdump
SIZE	= ${CPATH}/msp430-elf-size
# QEMU	= qemu-system-msp430-elf

ifdef DEBUG
DEBUGFLAGS = -Og -g
else
DEBUGFLAGS = -Os -flto
endif

MCU ?= msp430fr5969
CXXFLAGS = -mmcu=${MCU} -std=c++${CXXSTD} ${DEBUGFLAGS} -I../ -Wall -Wextra -Wpedantic -Werror