CONFIG ?= Release
BUILD_DIR_BASE = build
BUILD_DIR = $(BUILD_DIR_BASE)_$(CONFIG)

.PHONY: all
all: config build test

.PHONY: config
config:
	cmake -S. -B$(BUILD_DIR) -DCMAKE_BUILD_TYPE:STRING=$(CONFIG)

.PHONY: build
build:
	cmake --build $(BUILD_DIR) --config $(CONFIG) -- -j

.PHONY: avr
avr:
	mkdir -p build_avr
	avr-gcc --version
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/algorithm -I. examples/algorithm.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/array -I. examples/array.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/stm32_rtos -I. examples/experimental/stm32_rtos.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/numeric -I. examples/numeric.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/string -I. examples/string.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/tuple -I. examples/tuple.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/type_traits -I. examples/type_traits.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/vector -I. examples/vector.cpp

.PHONY: test
test:
	cd $(BUILD_DIR) && ctest -C $(CONFIG)

.PHONY: coverage
coverage:
	cmake -S . -G Ninja -B$(BUILD_DIR_BASE)_coverage -DTOBANTEAUDIO_ETL_BUILD_COVERAGE=ON
	cmake --build $(BUILD_DIR_BASE)_coverage
	cd $(BUILD_DIR_BASE)_coverage && lcov -c -i -d . --base-directory . -o base_cov.info
	cd $(BUILD_DIR_BASE)_coverage && ctest
	cd $(BUILD_DIR_BASE)_coverage && lcov -c -d . --base-directory . -o test_cov.info
	cd $(BUILD_DIR_BASE)_coverage && lcov -a base_cov.info -a test_cov.info -o cov.info
	cd $(BUILD_DIR_BASE)_coverage && lcov --remove cov.info "*3rd_party/*" -o cov.info
	cd $(BUILD_DIR_BASE)_coverage && lcov --remove cov.info "*c++*" -o cov.info
	cd $(BUILD_DIR_BASE)_coverage && lcov --remove cov.info "*v1*" -o cov.info
	cd $(BUILD_DIR_BASE)_coverage && lcov --remove cov.info "*Xcode.app*" -o cov.info

.PHONY: report
report:
	cd $(BUILD_DIR_BASE)_coverage && genhtml cov.info --output-directory lcov

.PHONY: tidy
tidy:
	cd $(BUILD_DIR) && ../scripts/run-clang-tidy.py ../tests -p . -fix -header-filter="etl/.*"
	cd $(BUILD_DIR) && ../scripts/run-clang-tidy.py ../examples -p . -fix -header-filter="etl/.*"

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)	
	rm -rf build_avr

.PHONY: stats
stats:
	cloc --exclude-dir=3rd_party,build_Debug,build_Release,build,venv,.vscode .

.PHONY: format
format:
	find etl -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i
	find examples -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i
	find tests -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i