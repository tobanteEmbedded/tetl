CXXFLAGS ?= -std=c++17 -g -O1 -fsanitize=fuzzer,address
CXXWARNINGS = -Wall -Wextra -Wpedantic

INCLUDES = -I../

.PHONY: all
all:
	$(CXX) $(CXXFLAGS) $(CXXWARNINGS) $(INCLUDES) main.cpp