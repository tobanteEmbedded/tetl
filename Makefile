CONFIG ?= debug
BUILD_DIR_BASE = cmake-build
BUILD_DIR ?= $(BUILD_DIR_BASE)-$(CONFIG)

ifneq (,$(findstring clang,$(CXX)))
    LCOV = lcov --gcov-tool llvm-gcov.sh
else
    LCOV = lcov
endif
COVERAGE_DIR=$(BUILD_DIR_BASE)-coverage

CLANG_VERSION ?=
CLANG_TIDY_ARGS += -clang-tidy-binary clang-tidy${CLANG_VERSION}
CLANG_TIDY_ARGS += -clang-apply-replacements-binary clang-apply-replacements${CLANG_VERSION}
CLANG_TIDY_ARGS += -j $(shell nproc) -quiet
CLANG_TIDY_ARGS += -p $(BUILD_DIR) -header-filter $(shell realpath ./etl)

STANDARDESE_BIN ?= standardese

.PHONY: all
all: config build test

.PHONY: config
config:
	cmake -S. -B$(BUILD_DIR) -D CMAKE_BUILD_TYPE:STRING=$(CONFIG) -D CMAKE_CXX_STANDARD=20

.PHONY: build
build:
	cmake --build $(BUILD_DIR) --config $(CONFIG) --parallel 6

.PHONY: test
test:
	cd $(BUILD_DIR) && ctest -C $(CONFIG)


.PHONY: coverage
coverage:
	cmake -S . -G Ninja -B cmake-build-coverage -D CMAKE_BUILD_TYPE=Debug -D TETL_BUILD_COVERAGE=TRUE -D CMAKE_CXX_STANDARD=20
	cmake --build cmake-build-coverage --parallel 6
	cd cmake-build-coverage && ctest

.PHONY: coverage-html
coverage-html: coverage
	cd cmake-build-coverage && gcovr --html --html-details --exclude-unreachable-branches -o coverage.html -r ../etl -j ${shell nproc} -s .

.PHONY: coverage-xml
coverage-xml: coverage
	cd cmake-build-coverage && gcovr --xml-pretty --exclude-unreachable-branches -o coverage.xml  -r ../etl -j ${shell nproc} -s .

.PHONY: doxygen
doxygen:
	mkdir -p cmake-build-doxygen/etl
	mkdir -p cmake-build-doxygen/pre
	mkdir -p cmake-build-doxygen/out
	python scripts/doxygen-preprocess.py
	cp Doxyfile.in cmake-build-doxygen/
	find cmake-build-doxygen/etl -iname '*.hpp' | xargs clang-format-12 -i
	cd cmake-build-doxygen && doxygen Doxyfile.in

.PHONY: standardese
standardese:
	rm -rf cmake-build-standardese
	mkdir cmake-build-standardese
	cd cmake-build-standardese && ${STANDARDESE_BIN} -I $(shell realpath .) --config $(shell realpath ./standardese.ini) -DTETL_FREERTOS_USE_STUBS=1 $(shell realpath ./etl)
	./scripts/standardese-md.py

.PHONY: docs
docs:
	rm -rf build-doxygen
	doxygen Doxyfile

.PHONY: tidy-check
tidy-check:
	 ./scripts/run-clang-tidy.py ${CLANG_TIDY_ARGS} $(shell realpath ./examples)
	 ./scripts/run-clang-tidy.py ${CLANG_TIDY_ARGS} $(shell realpath ./tests)

.PHONY: tidy-fix
tidy-fix:
	 ./scripts/run-clang-tidy.py -fix ${CLANG_TIDY_ARGS} $(shell realpath ./examples)
	 ./scripts/run-clang-tidy.py -fix ${CLANG_TIDY_ARGS} $(shell realpath ./tests)


.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) build_avr build-doc cmake-build-doxygen cmake-build-standardese


.PHONY: stats
stats:
	cloc --by-file --vcs=git .

.PHONY: format
format:
	find etl -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i
	find examples -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i
	find tests -iname '*.hpp' -o -iname '*.cpp' | xargs clang-format -i