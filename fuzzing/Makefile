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
	$(CXX) $(CXXFLAGS) -I ../include -o bin/fuzz_algorithm src/fuzz_algorithm.cpp
	$(CXX) $(CXXFLAGS) -I ../include -o bin/fuzz_bitset src/fuzz_bitset.cpp
	$(CXX) $(CXXFLAGS) -I ../include -o bin/fuzz_from_chars src/fuzz_from_chars.cpp
	$(CXX) $(CXXFLAGS) -I ../include -o bin/fuzz_string_view src/fuzz_string_view.cpp
	$(CXX) $(CXXFLAGS) -I ../include -o bin/fuzz_to_chars src/fuzz_to_chars.cpp

.PHONY: fuzz
fuzz: build
	$(LCOV) -c -i -d . --base-directory . -o bin/base_cov.info --ignore-errors inconsistent
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/fuzz_algorithm -max_total_time=$(MAXTIME)
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/fuzz_bitset -max_total_time=$(MAXTIME)
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/fuzz_from_chars -max_total_time=$(MAXTIME)
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/fuzz_string_view -max_total_time=$(MAXTIME)
	LLVM_PROFILE_FILE="bin/%p-%m.profraw" ./bin/fuzz_to_chars -max_total_time=$(MAXTIME)
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
