# CONTRIBUTING

## Quick Start

```sh
# Build & run all unit tests and examples.
cd tetl
cmake -S . -B cmake-build-debug -D CMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-debug
cd cmake-build-debug; ctest; cd -
```

### Project Layout

```sh
├── 3rd_party   # Catch2 submodule
├── cmake       # Compiler config
├── etl         # Actual source code
├── examples    # Simple demos which only require a libc & etl
├── fuzzing     # LLVM libFuzzer runner
├── scripts     # Coverage, clang-tidy & docs scripts
└── tests       # Unit tests
```

## Tools

### clang-tidy

TODO

### clang-format

TODO

### lcov

TODO

### doxygen & standardese

TODO

## Coding Style

- Trailing return type is used everywhere. Including if type is `void`
  - `auto foo() -> double;`
  - `auto nothing() -> void;`
- Naming conventions:
  - Public interface matches the STL conventions
  - Checked via `clang-tidy`. See [.clang-tidy](./.clang-tidy) config.
  - Local variables & parameters are `camelBack`
  - Template arguments are `CamelCase`
  - Private members have a "_" suffix. e.g. `int val_;`
