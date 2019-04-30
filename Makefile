EXAMPLE_DIR = examples
TEST_DIR = tests
INCLUDE_DIR = src

BUILD_DIR = build
BUILD_OPTIONS = --std=c++17 -O0 -g
BUILD_WARNINGS = -Wall -Wextra

AVR_GCC = avr-gcc
AVR_BUILD_DIR = build_avr

all:
	cmake -B$(BUILD_DIR) -H.
	cmake --build $(BUILD_DIR)/

avr:
	# CREATE BUILD DIR
	mkdir -p $(AVR_BUILD_DIR)
	# BUILD EXAMPLES
	$(AVR_GCC) $(BUILD_OPTIONS) $(BUILD_WARNINGS) -o $(AVR_BUILD_DIR)/example-avr-algorithm -I$(INCLUDE_DIR) $(EXAMPLE_DIR)/algorithm.cpp
	$(AVR_GCC) $(BUILD_OPTIONS) $(BUILD_WARNINGS) -o $(AVR_BUILD_DIR)/example-avr-array -I$(INCLUDE_DIR) $(EXAMPLE_DIR)/array.cpp
	$(AVR_GCC) $(BUILD_OPTIONS) $(BUILD_WARNINGS) -o $(AVR_BUILD_DIR)/example-avr-numeric -I$(INCLUDE_DIR) $(EXAMPLE_DIR)/numeric.cpp
	$(AVR_GCC) $(BUILD_OPTIONS) $(BUILD_WARNINGS) -o $(AVR_BUILD_DIR)/example-avr-string -I$(INCLUDE_DIR) $(EXAMPLE_DIR)/string.cpp
	$(AVR_GCC) $(BUILD_OPTIONS) $(BUILD_WARNINGS) -o $(AVR_BUILD_DIR)/example-avr-type_traits -I$(INCLUDE_DIR) $(EXAMPLE_DIR)/type_traits.cpp
	# BUILD TESTS
	$(AVR_GCC) $(BUILD_OPTIONS) $(BUILD_WARNINGS) -o $(AVR_BUILD_DIR)/test-avr-array -I$(INCLUDE_DIR) $(TEST_DIR)/test_array.cpp
	$(AVR_GCC) $(BUILD_OPTIONS) $(BUILD_WARNINGS) -o $(AVR_BUILD_DIR)/test-avr-definitions -I$(INCLUDE_DIR) $(TEST_DIR)/test_definitions.cpp
	$(AVR_GCC) $(BUILD_OPTIONS) $(BUILD_WARNINGS) -o $(AVR_BUILD_DIR)/test-avr-string -I$(INCLUDE_DIR) $(TEST_DIR)/test_string.cpp
	$(AVR_GCC) $(BUILD_OPTIONS) $(BUILD_WARNINGS) -o $(AVR_BUILD_DIR)/test-avr-constexpr_string -I$(INCLUDE_DIR) $(TEST_DIR)/test_constexpr_string.cpp

test:
	cd $(BUILD_DIR) && ctest 

clean:
	rm -rf $(BUILD_DIR)/*	
	rm -rf $(AVR_BUILD_DIR)/*