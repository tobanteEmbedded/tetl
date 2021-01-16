ifdef DEBUG
DEBUGFLAGS = -Og -g
else
DEBUGFLAGS = -Os -flto
endif

ifndef CXXSTD
	CXXSTD := 17
endif

include mk/avr_atmega328p.mk

EXAMPLES 	+= algorithm
EXAMPLES 	+= array
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

EXE 	:= ${addsuffix .elf, ${EXAMPLES}}

.PHONY: all
all: ${EXE}

.PRECIOUS: ${EXE}
%.elf: %.cpp
	${CXX} ${CXXFLAGS} -o $@ $^

.PHONY: clean
clean:
	find . -type f -name '*.elf' -exec rm {} +
