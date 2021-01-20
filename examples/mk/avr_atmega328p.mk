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

MCU ?= atmega328p
CXXFLAGS = -mmcu=${MCU} -std=c++${CXXSTD} ${DEBUGFLAGS} -I../ -Wall -Wextra -Wpedantic -Werror
