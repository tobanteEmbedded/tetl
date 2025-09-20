# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

CXX = clang++-21
CXXFLAGS = -std=c++26 -g3 -O1 -fsanitize=fuzzer,address,undefined -ftest-coverage -fcoverage-mapping -fprofile-arcs -fprofile-instr-generate
LCOV = lcov --gcov-tool ../scripts/llvm-gcov.sh
MAXTIME ?= 20

.PHONY: bin
bin:
	mkdir -p bin

.PHONY: build
build: bin
	$(CXX) $(CXXFLAGS) -I ../include -o bin/algorithm.fuzz src/algorithm.fuzz.cpp
	$(CXX) $(CXXFLAGS) -I ../include -o bin/bitset.fuzz src/bitset.fuzz.cpp
	$(CXX) $(CXXFLAGS) -I ../include -o bin/from_chars.fuzz src/from_chars.fuzz.cpp
	$(CXX) $(CXXFLAGS) -I ../include -o bin/string_view.fuzz src/string_view.fuzz.cpp
	$(CXX) $(CXXFLAGS) -I ../include -o bin/to_chars.fuzz src/to_chars.fuzz.cpp

.PHONY: fuzz
fuzz: build
	$(LCOV) -c -i -d . --base-directory . -o bin/base_cov.info --ignore-errors inconsistent
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/algorithm.fuzz -max_total_time=$(MAXTIME)
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/bitset.fuzz -max_total_time=$(MAXTIME)
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/from_chars.fuzz -max_total_time=$(MAXTIME)
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/string_view.fuzz -max_total_time=$(MAXTIME)
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/to_chars.fuzz -max_total_time=$(MAXTIME)
	$(LCOV) -c -d . --base-directory . -o bin/fuzz_cov.info --ignore-errors inconsistent
	$(LCOV) -a bin/base_cov.info -a bin/fuzz_cov.info -o bin/cov.info --ignore-errors inconsistent
	$(LCOV) --remove bin/cov.info "*clang*" -o bin/cov.info --ignore-errors inconsistent
	$(LCOV) --remove bin/cov.info "*c++*" -o bin/cov.info --ignore-errors inconsistent


.PHONY: report
report: fuzz
	genhtml bin/cov.info --output-directory lcov --ignore-errors inconsistent

.PHONY: clean
clean:
	rm -rf bin lcov *.profraw
