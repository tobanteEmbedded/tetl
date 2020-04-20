CONFIG ?= Release
BUILD_DIR = build_$(CONFIG)

CM_GENERATOR ?= Ninja 

.PHONY: all
all: config build test

.PHONY: config
config:
	cmake -H. -B$(BUILD_DIR) -G$(CM_GENERATOR) -DCMAKE_BUILD_TYPE:STRING=$(CONFIG)

.PHONY: build
build:
	cmake --build $(BUILD_DIR) --config $(CONFIG)

.PHONY: avr
avr:
	mkdir -p build_avr
	avr-gcc --version
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/example-avr-algorithm -I. examples/algorithm.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/example-avr-array -I. examples/array.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/example-avr-numeric -I. examples/numeric.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/example-avr-string -I. examples/string.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/example-avr-tuple -I. examples/tuple.cpp
	avr-gcc --std=c++17 -Os -Wall -Wextra -Wpedantic -o build_avr/example-avr-type_traits -I. examples/type_traits.cpp

.PHONY: test
test:
	cd $(BUILD_DIR) && ctest -C Debug

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)	
	rm -rf build_avr

.PHONY: stats
stats:
	cloc --exclude-dir=3rd_party,build_Debug,build_Release,.vscode .

.PHONY: format
format:
	find taetl -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i
	find examples -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i
	find tests -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i