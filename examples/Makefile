ifndef CXXSTD
	CXXSTD := 17
endif

ifdef ARM
include mk/arm_stm32f103.mk
endif

ifdef AVR
include mk/avr_atmega328p.mk
endif

ifdef MSP430
include mk/msp430.mk
endif

ifdef X86
include mk/x86_linux.mk
endif


EXAMPLES 	+= algorithm
EXAMPLES 	+= all_headers
EXAMPLES 	+= array
EXAMPLES 	+= bitset
EXAMPLES 	+= cassert
EXAMPLES 	+= chrono
EXAMPLES 	+= map
EXAMPLES 	+= numeric
EXAMPLES 	+= optional
EXAMPLES 	+= set
EXAMPLES 	+= source_location
EXAMPLES 	+= string
EXAMPLES 	+= tuple
EXAMPLES 	+= type_traits
EXAMPLES 	+= utility
EXAMPLES 	+= vector


ifdef ARM
EXAMPLES 	+= experimental/stm32_freertos
EXAMPLES 	+= memory
endif

ifdef AVR
EXE := ${addsuffix .elf, ${EXAMPLES}}
endif

ifdef ARM
EXE := ${addsuffix .o, ${EXAMPLES}}
endif

ifdef MSP430
EXE := ${addsuffix .o, ${EXAMPLES}}
endif

ifdef X86
EXE := ${addsuffix .elf, ${EXAMPLES}}
endif

.PHONY: all
all: ${EXE}

%.elf: %.cpp
	${CXX} ${CXXFLAGS} -o $@ $^

%.o: %.cpp
	${CXX} -c ${CXXFLAGS} -o $@ $^

.PHONY: clean
clean:
	find . -type f -name '*.o' -exec rm {} +
	find . -type f -name '*.elf' -exec rm {} +
