ifdef DEBUG
DEBUGFLAGS = -Og -g
else
DEBUGFLAGS = -O3 -flto
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

CXXFLAGS = -std=c++${CXXSTD} ${DEBUGFLAGS} -I../ ${WARNINGFLAGS}