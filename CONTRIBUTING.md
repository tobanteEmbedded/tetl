# Contributing

## Quick Start

```sh
cmake -S . -B build -G "Ninja Multi-Config"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

### Project Layout

```sh
├── benchmarks  # Compile-time benchmarks
├── cmake       # Compiler config
├── docs        # Documentation
├── examples    # Simple demos which only require libc & tetl
├── fuzzing     # LLVM libFuzzer runner
├── include     # Source code
├── scripts     # Coverage & clang-tidy
└── tests       # Unit tests
```

## Coding Style

- Trailing return type is used everywhere. Including if type is `void`
  - `auto foo() -> double;`
  - `auto nothing() -> void;`
- Naming conventions:
  - Public interface matches the STL conventions
  - Checked via `clang-tidy`. See [.clang-tidy](./.clang-tidy) config.
  - Local variables & parameters are `camelBack`
  - Template arguments are `CamelCase`
  - Private members have a "\_" prefix. e.g. `int _val;`

## Tools

### clang-tidy

```sh
cmake -S . -B cmake-build-tidy -G "Unix Makefiles" -D CMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-tidy --parallel 8
run-clang-tidy -fix -j 8 -quiet -p cmake-build-tidy -header-filter $(realpath .) $(realpath .)
```

### pre-commit

```sh
pre-commit install
pre-commit run -a
```

### doxygen

```sh
git clone https://github.com/jothepro/doxygen-awesome-css.git 3rd_party/doxygen-awesome-css
doxygen Doxyfile
open build-doxygen/html/index.html
```
