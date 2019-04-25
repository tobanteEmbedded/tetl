BUILD_DIR = build

all:
	cmake -B$(BUILD_DIR) -H.
	cmake --build $(BUILD_DIR)/

test:
	cd $(BUILD_DIR) && ctest 

clean:
	rm -rf $(BUILD_DIR)/*