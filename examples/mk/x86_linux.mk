ifdef DEBUG
DEBUGFLAGS = -Og -g
else
DEBUGFLAGS = -O3 -flto
endif

CXXFLAGS = -std=c++${CXXSTD} ${DEBUGFLAGS} -I../ -Wall -Wextra -Wpedantic -Werror