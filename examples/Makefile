ifdef DEBUG
DEBUGFLAGS = -Og -g
else
DEBUGFLAGS = -Os -flto
endif

ifndef CXXSTD
	CXXSTD := 17
endif

ifdef AVR
include mk/avr_atmega328p.mk
endif

ifdef ARM
include mk/arm_stm32f103.mk
endif


EXAMPLES 	+= algorithm
EXAMPLES 	+= array
EXAMPLES 	+= bitset
EXAMPLES 	+= chrono
EXAMPLES 	+= map
EXAMPLES 	+= numeric
EXAMPLES 	+= optional
EXAMPLES 	+= set
EXAMPLES 	+= string
EXAMPLES 	+= tuple
EXAMPLES 	+= type_traits
EXAMPLES 	+= utility
EXAMPLES 	+= vector

ifdef AVR
EXE := ${addsuffix .elf, ${EXAMPLES}}
endif

ifdef ARM
EXE := ${addsuffix .o, ${EXAMPLES}}
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
