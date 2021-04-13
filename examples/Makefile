ifndef CXXSTD
	CXXSTD := 17
endif

ifdef AVR
include mk/avr_atmega328p.mk
endif

ifdef ARM
include mk/arm_stm32f103.mk
endif

ifdef X86
include mk/x86_linux.mk
endif


EXAMPLES 	+= algorithm
EXAMPLES 	+= array
EXAMPLES 	+= bitset
EXAMPLES 	+= cassert
EXAMPLES 	+= chrono
EXAMPLES 	+= map
EXAMPLES 	+= memory
EXAMPLES 	+= numeric
EXAMPLES 	+= optional
EXAMPLES 	+= set
EXAMPLES 	+= string
EXAMPLES 	+= tuple
EXAMPLES 	+= type_traits
EXAMPLES 	+= utility
EXAMPLES 	+= vector

EXAMPLES 	+= experimental/stm32_rtos

ifdef AVR
EXE := ${addsuffix .elf, ${EXAMPLES}}
endif

ifdef ARM
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
