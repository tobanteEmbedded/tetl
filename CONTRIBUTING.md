<!-- SPDX-License-Identifier: BSL-1.0 -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch -->

# Contributing

## Quick Start

```sh
# Desktop
cmake -S . -B cmake-build-desktop -G "Ninja Multi-Config"
cmake --build cmake-build-desktop --config Debug
ctest --test-dir cmake-build-desktop -C Debug --output-on-failure
```

```sh
# Emscripten
emcmake cmake -S . -B cmake-build-emscripten -G "Ninja Multi-Config" -D CMAKE_CXX_FLAGS="-fno-exceptions"
cmake --build cmake-build-emscripten --config Debug
ctest --test-dir cmake-build-emscripten -C Debug --output-on-failure
```

```sh
# AVR
cmake -S . -B cmake-build-avr-gcc -G "Ninja Multi-Config" -D CMAKE_TOOLCHAIN_FILE="cmake/toolchain/atmega2560.cmake"
cmake --build cmake-build-avr-gcc --config Debug
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

## Tests

Boilerplate for unit tests:

```cpp
// SPDX-License-Identifier: BSL-1.0
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::cmp_equal(1, T(1)));
    CHECK_FALSE(etl::cmp_equal(-1, T(1)));
    CHECK_NOEXCEPT(etl::cmp_equal(-1, T(1)));
    CHECK_SAME_TYPE(decltype(etl::cmp_equal(-1, T(1))), bool);

    // more checks
    // ...

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    // more custom types if needed
    // ...

    return true;
}

} // namespace

auto main() -> int
{
    // runs both assert & static_assert
    STATIC_CHECK(test_all());

    // runs only assert, use if constexpr is not supported
    // CHECK(test_all());
    return 0;
}
```

## Tools

### CMake Presets

```sh
cmake --list-presets=all .
cmake --preset desktop
cmake --build --preset desktop
ctest --preset desktop
```

### clang-tidy

```sh
cmake -S . -B cmake-build-tidy -G "Unix Makefiles" -D CMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-tidy --parallel $(nproc)
run-clang-tidy -fix -j $(nproc) -quiet -p cmake-build-tidy -header-filter $(realpath .) $(realpath .)
```

### coverage

```sh
# build with coverage flags
cmake -S . -B cmake-build-coverage -G Ninja -D CMAKE_BUILD_TYPE=Debug -D CMAKE_CXX_STANDARD=23 -D CMAKE_CXX_FLAGS="--coverage" -D CMAKE_EXE_LINKER_FLAGS="--coverage"
cmake --build cmake-build-coverage --parallel $(nproc)
ctest --test-dir cmake-build-coverage -C Debug --output-on-failure -j $(nproc)

# run gcov
gcovr --html-details -e ".*_3rd_party*" --exclude-unreachable-branches -r . -s cmake-build-coverage -o cmake-build-coverage/coverage.html -j $(nproc)

# or grcov (faster)
grcov . -s . --binary-path ./cmake-build-coverage/bin/ -t html --ignore-not-existing -o ./cmake-build-coverage/html/ --ignore '*_3rd_party/*' --threads $(nproc)
```

### libFuzzer

```sh
MAXTIME=20 make -C fuzzing clean report
firefox fuzzing/lcov/index.html
```

### pre-commit

```sh
pre-commit install
pre-commit run -a
```

### doxygen

```sh
doxygen Doxyfile
open build-doxygen/html/index.html
```

### VS Code

Enable one of the following options in `.vscode/settings.json`:

```json
"cmake.useCMakePresets": "always"
"cmake.useCMakePresets": "never"
```

## Coding Style

- Trailing return type is used **everywhere**:
  - `auto func() {}`
  - `auto func() -> void;`
  - `auto func() -> double;`
  - `auto func() -> auto&;`
  - `auto func() -> decltype(auto);`
- Keyword `class` is **banned**:
  - `struct foo {};`
  - `enum struct foo { baz, baz };`
  - `template<typename T>`
- Naming conventions:
  - Public interface matches the STL conventions
  - Checked via `clang-tidy`. See [.clang-tidy](./.clang-tidy) config.
  - Local variables & parameters are `camelBack`
  - Template arguments are `CamelCase`
  - Private members have a "\_" prefix. e.g. `int _val;`
