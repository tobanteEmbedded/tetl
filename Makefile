CONFIG ?= Release
BUILD_DIR_BASE = build
BUILD_DIR = $(BUILD_DIR_BASE)_$(CONFIG)

.PHONY: all
all: config build test

.PHONY: config
config:
	cmake -S. -B$(BUILD_DIR) -DCMAKE_BUILD_TYPE:STRING=$(CONFIG) -DTOBANTEAUDIO_ETL_BUILD_CPP20=ON

.PHONY: build
build:
	cmake --build $(BUILD_DIR) --config $(CONFIG) -- -j6

.PHONY: arm
arm:
	$(MAKE) -C examples/projects/arm_make clean all

.PHONY: avr
avr:
	mkdir -p build_avr/17
	mkdir -p build_avr/20
	avr-gcc --version
	# 17
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/algorithm -I. examples/algorithm.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/array -I. examples/array.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/chrono -I. examples/chrono.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/stm32_rtos -I. examples/experimental/stm32_rtos.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/numeric -I. examples/numeric.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/map -I. examples/map.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/set -I. examples/set.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/string -I. examples/string.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/tuple -I. examples/tuple.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/type_traits -I. examples/type_traits.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/17/vector -I. examples/vector.cpp
	# 20
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/algorithm -I. examples/algorithm.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/array -I. examples/array.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/chrono -I. examples/chrono.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/stm32_rtos -I. examples/experimental/stm32_rtos.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/numeric -I. examples/numeric.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/map -I. examples/map.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/set -I. examples/set.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/string -I. examples/string.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/tuple -I. examples/tuple.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/type_traits -I. examples/type_traits.cpp
	avr-gcc --std=c++2a -Os -Wall -Wextra -Wpedantic -o build_avr/20/vector -I. examples/vector.cpp

.PHONY: test
test:
	cd $(BUILD_DIR) && ctest -C $(CONFIG) -j8

ifneq (,$(findstring clang,$(CXX)))
    LCOV = lcov --gcov-tool llvm-gcov.sh
else
    LCOV = lcov
endif
COVERAGE_DIR=$(BUILD_DIR_BASE)_coverage
.PHONY: coverage
coverage:
	mkdir -p $(COVERAGE_DIR)
	cmake -S . -G Ninja -B$(COVERAGE_DIR) -DTOBANTEAUDIO_ETL_BUILD_COVERAGE=ON -DTOBANTEAUDIO_ETL_BUILD_CPP20=ON
	cmake --build $(COVERAGE_DIR) -- -j12
	cd $(COVERAGE_DIR) && $(LCOV) -c -i -d . --base-directory . -o base_cov.info
	cd $(COVERAGE_DIR) && ctest -j12
	cd $(COVERAGE_DIR) && $(LCOV) -c -d . --base-directory . -o test_cov.info
	cd $(COVERAGE_DIR) && $(LCOV) -a base_cov.info -a test_cov.info -o cov.info
	cd $(COVERAGE_DIR) && $(LCOV) --remove cov.info "*3rd_party/*" -o cov.info
	cd $(COVERAGE_DIR) && $(LCOV) --remove cov.info "*c++*" -o cov.info
	cd $(COVERAGE_DIR) && $(LCOV) --remove cov.info "*v1*" -o cov.info
	cd $(COVERAGE_DIR) && $(LCOV) --remove cov.info "*Xcode.app*" -o cov.info
	cd $(COVERAGE_DIR) && $(LCOV) --remove cov.info "*test_*" -o cov.info

.PHONY: report
report:
	cd $(BUILD_DIR_BASE)_coverage && genhtml cov.info --output-directory lcov

.PHONY: docs
docs:
	doxygen Doxyfile.in

.PHONY: tidy
tidy:
	cp .clang-tidy $(BUILD_DIR)/
	cd $(BUILD_DIR) && ../scripts/run-clang-tidy.py ../examples -p . -fix -header-filter="etl/.*"
	# cd $(BUILD_DIR) && ../scripts/run-clang-tidy.py ../tests -p . -fix -header-filter="etl/.*"

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf build_avr
	rm -rf build-doc

.PHONY: stats
stats:
	cloc --by-file cmake docs etl fuzzing tests README.md

.PHONY: format
format:
	find etl -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i
	find examples -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i
	find tests -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i