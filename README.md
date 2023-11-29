# TETL - Embedded Template Library

Tobante's embedded template library. A STL-like C++ template library designed for embedded devices with limited resources. Supports freestanding and hosted environments.

- [Quick Start](#quick-start)
- [Status](#status)
  - [Hosted](#hosted)
  - [Freestanding](#freestanding)
  - [Analysis](#analysis)
- [Design Goals](#design-goals)
  - [Error Handling](#error-handling)
  - [Near Future](#near-future)
  - [Far Future](#far-future)
- [Project Integration](#project-integration)
  - [Command Line](#command-line)
  - [CMake](#cmake)
  - [PlatformIO](#platformio)
- [Header Overview](#header-overview)
- [Header Detail](#header-detail)

## Quick Start

```cpp
#include <etl/algorithm.hpp>  // for count_if
#include <etl/array.hpp>      // for array

auto main() -> int {
  auto const numbers = etl::array{1, 2, 3, 4, 5};
  auto const greater_two = [] (auto const v) { return v > 2; };
  return etl::count_if(begin(numbers), end(numbers), greater_two);
}
```

```sh
g++ -Wall -Wextra -Wpedantic -std=c++20 -I path/to/tetl/include main.cpp
```

For examples look at the [examples](./examples) subdirectory or the test files in [tests](./tests). The [API reference](https://tobanteembedded.github.io/tetl-docs/) is currently work in progress. I'm switching from doxygen to standardese, which still has some bugs, so some parts of the docs may still be missing.

## Status

| **License**                                                                                                                                 | **Lines of Code**                                    | **Progress**                                                                                                        | **Documentation**                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [![License](https://img.shields.io/badge/License-Boost%201.0-lightblue.svg)](https://github.com/tobanteEmbedded/tetl/blob/main/LICENSE.txt) | ![LOC](https://sloc.xyz/github/tobanteEmbedded/tetl) | [Spreadsheet](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing) | [API Reference](https://tobanteembedded.github.io/tetl-docs/) |

### Hosted

#### x64

| **Platform** |                                                                                    **Status**                                                                                    |              **Notes**              |
| :----------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :---------------------------------: |
|  **Linux**   |    [![Linux X64](https://github.com/tobanteEmbedded/tetl/actions/workflows/linux-x64.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/linux-x64.yml)    |     GCC 11/12 & Clang 13/14/16      |
|  **macOS**   |    [![macOS X64](https://github.com/tobanteEmbedded/tetl/actions/workflows/macos-x64.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/macos-x64.yml)    |            AppleClang 14            |
| **Windows**  | [![Windows X64](https://github.com/tobanteEmbedded/tetl/actions/workflows/windows-x64.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/windows-x64.yml) | Visual Studio 2022, ClangCL & Clang |

### Freestanding

| **Platform** |                                                                                                **Status**                                                                                                | **Notes** |
| :----------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :-------: |
|   **ARM**    |     [![ARM Freestanding](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-arm.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-arm.yml)      |  GCC 12   |
|   **AVR**    |     [![AVR Freestanding](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-avr.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-avr.yml)      |  GCC 12   |
|  **MSP430**  | [![MSP430 Freestanding](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-msp430.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-msp430.yml) |  GCC 12   |

### Analysis

|        **Type**        |                                                                                                   **Status**                                                                                                   | **Notes** |
| :--------------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :-------: |
|      **Coverage**      |                               [![codecov](https://codecov.io/gh/tobanteEmbedded/tetl/branch/main/graph/badge.svg?token=f1QAWTtpIo)](https://codecov.io/gh/tobanteEmbedded/tetl)                                |  GCC 11   |
|     **Sanitizers**     | [![Sanitizers (ASAN/UBSAN)](https://github.com/tobanteEmbedded/tetl/actions/workflows/linux-x64-sanitizers.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/linux-x64-sanitizers.yml) | Clang 16  |
|     **Clang-Tidy**     |                 [![Clang-Tidy](https://github.com/tobanteEmbedded/tetl/actions/workflows/clang-tidy.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/clang-tidy.yml)                  | Clang 16  |
| **Clang -Weverything** |      [![Clang -Weverything](https://github.com/tobanteEmbedded/tetl/actions/workflows/clang-weverything.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/clang-weverything.yml)       | Clang 16  |

> **_NOTE:_** All test are compiled in debug and release mode with at least `-Wall -Wextra -Wpedantic -Werror` or `/W3 /WX`. The full list of warning flags can be found in the CMake configuration: [cmake/compiler_warnings.cmake](./cmake/compiler_warnings.cmake). Hosted platforms run all tests & examples, while freestanding builds only compile (ARM & AVR) and link (AVR) the example files.

## Design Goals

- 100% portable (no STL headers required, minimum of C headers)
- Header only
- C++20 and beyond (freestanding or hosted)
- Similar API to the STL
- No dynamic memory
- `constexpr` all the things
- Minimize undefined behavoir. See [Error Handling](#error-handling)
- Easy desktop development (cmake)

It all started when I wanted to have a vector without dynamic memory. At that time I didn't know that proposals like [github.com/gnzlbg/static_vector](https://github.com/gnzlbg/static_vector) where in the making. My actual goal has turned into a mammoth project. A standard library for microcontrollers and other embedded environments. The API is, as far as it is technically feasible, identical to the STL. All algorithms work identically, pair and friend are available and containers like set, map and vector are also implemented, but with different names.

All containers work only with memory on the stack. This means that their size must be known at compile time. Furthermore I assume an environment in which exceptions and
RTTI migth be disabled. This results in the problem that not all members of a container can be implemented the same way as they are in the STL. Any function that returns a reference to a sequence element has the ability to throw exceptions in a normal hosted environment if the index is out of bounds. If exceptions are disabled, this is not possible. For now, my solution to this problem is to delegate to the user. Unsafe methods like `etl::static_vector::operator[]` are still available (with asserts in debug builds), while throwing methods like `etl::static_vector::at` are not implemented. This is currently subject to change. See [Error Handling](#error-handling) for more details.

Unlike LLVMs `SmallVector`, `etl::static_vector` & friends do not have a base class which they can slice to. My plan is to add mutable view-like non-owning types for each container. A `etl::static_vector` we would have a `vector_ref` which would work mostly like a `span`, but would also provide the vector interface. I don't want to name the types `*_view`, since the word `view` implies non-mutable in standard containers like `string_view`. None of the container_ref types have been implemented yet.

The headers [etl/algorithm.hpp](./include/etl/algorithm.hpp) and [etl/numeric.hpp](./include/etl/numeric.hpp) provide all algorithms from the standard. Unlike implementations found in libstdc++ or libc++, mine are primarily optimized for code size and not runtime performance. Overloads with an `ExecutionPolicy` are not implemented.

Headers like [etl/chrono.hpp](./include/etl/chrono.hpp) and [etl/mutex.hpp](./include/etl/mutex.hpp) only provide classes & functions that can be implemented in a portable way. Platform specific functionality like `steady_clock` or `mutex` can be provided by the user. The user provided types should meet the requirements listed in [Named Requirements](https://en.cppreference.com/w/cpp/named_req) to work seamlessly with the types provided in the `etl` namespace.

The [etl/experimental](./include/etl/experimental) subdirectory includes libraries that use `etl` as their foundation. It can be thought of as a mini boost-like library collection. Everything is work in progress.

- Networking (buffers, ntoh, ...)
- Strong types
- STM32 HAL
- DSP DSL
- FreeRTOS Abstraction
  - Stubs for unittests run on desktop machines

### Error Handling

Since I assume that you might have exceptions disabled, I need a different way of reporting exceptional cases to you which occured deep inside the library. To keep the behavior of my library and actual STL implementations as close as possible, I've chosen to add a global assert/exception handler functions, which can be overriden by enabling the `TETL_ENABLE_CUSTOM_ASSERT_HANDLER` macro.

#### TODO

- ASSERT macro for debug checks
- EXCEPTION macro for debug & release checks

For more details about the global assertion handler `etl::tetl_assert_handler` & the assertion macro `TETL_ASSERT` see the [examples/cassert.cpp](./examples/cassert.cpp) file.

### Near Future

- Switch from `doxygen` to `standardese` as the documentation generator
- Fix `map`, `tuple`, `variant` & `format`
- Improve number <-> string conversions
- Add fuzzing tests to CI
  - Check that `etl` and `std` implementations produce the same output

### Far Future

- Replace Catch2 with custom unit testing library
  - This depends on a working implementation of `format` for reporting errors.
- Run unit test & examples on hardware or QEMU emulations.
  - Depends on the custom unit test library, since Catch2 is to big to fit onto most MCUs

## Project Integration

The following steps explain how to add `etl` to your project. Embedded or desktop.

```sh
cd path/to/your/project
mkdir 3rd_party
git submodule add https://github.com/tobanteEmbedded/tetl.git 3rd_party/tetl
```

### Command Line

```make
CXXFLAGS += -std=c++20 -I3rd_party/tetl
```

### CMake

Add `tetl` as a git submodule, then add these lines to your `CMakeLists.txt`:

```cmake
# tetl::etl is an interface target, so you can use it even if you
# have a custom toolchain in your CMake configuration. The target only sets the
# include path. No static library is created.

add_subdirectory(3rd_party/tetl/include EXCLUDE_FROM_ALL)
target_link_libraries(${YOUR_TARGET} tetl::etl)
```

### PlatformIO

Add `tetl` as a git submodule, then add these lines to your `platformio.ini`:

```ini
; Most Arduino code does not compile unless you have GNU extensions enabled.
[env:yourenv]
build_unflags = -std=gnu++11
build_flags = -std=gnu++20 -Wno-register -I 3rd_party/tetl
```

## Header Overview

|             **Header**              |       **Library**        |     **Status**     |                                       **Implementation Progress (Spreadsheet)**                                        |
| :---------------------------------: | :----------------------: | :----------------: | :--------------------------------------------------------------------------------------------------------------------: |
|       [algorithm](#algorithm)       |        Algorithms        | :heavy_check_mark: |  [algorithm](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1451123716)  |
|                 any                 |         Utility          |        :x:         |                                                                                                                        |
|           [array](#array)           |        Containers        | :heavy_check_mark: |    [array](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1320059600)    |
|               atomic                |          Atomic          |        :x:         |                                                                                                                        |
|               barrier               |          Thread          |        :x:         |                                                                                                                        |
|             [bit](#bit)             |         Numeric          | :heavy_check_mark: |     [bit](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1927645890)     |
|          [bitset](#bitset)          |         Utility          | :heavy_check_mark: |    [bitset](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=692946382)    |
|         [cassert](#cassert)         | Utility / Error Handling | :heavy_check_mark: |   [cassert](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=460740183)    |
|          [cctype](#cctype)          |         Strings          | :heavy_check_mark: |    [cctype](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=522168028)    |
|               cerrno                | Utility / Error Handling |        :x:         |                                                                                                                        |
|                cfenv                |         Numeric          |        :x:         |                                                          TODO                                                          |
|          [cfloat](#cfloat)          | Utility / Numeric Limits | :heavy_check_mark: |   [cfloat](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1012838019)    |
|        [charconv](#charconv)        |         Strings          | :heavy_check_mark: |   [charconv](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=345887816)   |
|          [chrono](#chrono)          |         Utility          | :heavy_check_mark: |   [chrono](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1279150724)    |
|              cinttypes              | Utility / Numeric Limits |        :x:         |                                                          TODO                                                          |
|         [climits](#climits)         | Utility / Numeric Limits | :heavy_check_mark: |   [climits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1904156895)   |
|               clocale               |       Localization       |        :x:         |                                                                                                                        |
|           [cmath](#cmath)           |         Numeric          | :heavy_check_mark: |    [cmath](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=868070087)     |
|         [compare](#compare)         |         Utility          | :heavy_check_mark: |   [compare](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1676133546)   |
|         [complex](#complex)         |         Numeric          | :heavy_check_mark: |   [complex](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1768885550)   |
|        [concepts](#concepts)        |         Concepts         | :heavy_check_mark: |   [concepts](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=73781271)    |
|         condition_variable          |          Thread          |        :x:         |                                                                                                                        |
|              coroutine              |        Coroutines        |        :x:         |                                                                                                                        |
|               csetjmp               |         Utility          |        :x:         |                                                                                                                        |
|               csignal               |         Utility          |        :x:         |                                                                                                                        |
|         [cstddef](#cstddef)         |         Utility          | :heavy_check_mark: |   [cstddef](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1660546405)   |
|         [cstdint](#cstdint)         | Utility / Numeric Limits | :heavy_check_mark: |   [cstdint](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2005735528)   |
|          [cstdio](#cstdio)          |       Input/Output       | :heavy_check_mark: |   [cstdio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1576270107)    |
|         [cstdlib](#cstdlib)         |         Utility          | :heavy_check_mark: |   [cstdlib](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1705155517)   |
|         [cstring](#cstring)         |         Strings          | :heavy_check_mark: |   [cstring](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1824871501)   |
|           [ctime](#ctime)           |         Utility          | :heavy_check_mark: |    [ctime](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1082109762)    |
|               cuchar                |         Strings          |        :x:         |                                                                                                                        |
|          [cwchar](#cwchar)          |         Strings          | :heavy_check_mark: |   [cwchar](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1105944467)    |
|         [cwctype](#cwctype)         |         Strings          | :heavy_check_mark: |   [cwctype](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1740196036)   |
|                deque                |        Containers        |        :x:         |                                                          TODO                                                          |
|       [exception](#exception)       | Utility / Error Handling | :heavy_check_mark: |   [exception](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing)    |
|              execution              |        Algorithms        |        :x:         |                                                                                                                        |
|        [expected](#expected)        | Utility / Error Handling | :heavy_check_mark: |  [expected](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1624993362)   |
|        [flat_set](#flat_set)        |        Conatiners        | :heavy_check_mark: |   [flat_set](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=291280131)   |
|        [flat_map](#flat_map)        |        Conatiners        | :heavy_check_mark: |  [flat_map](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1047136935)   |
|             filesystem              |        Filesystem        |        :x:         |                                                                                                                        |
|          [format](#format)          |         Strings          | :heavy_check_mark: |    [format](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=159875067)    |
|            forward_list             |        Containers        |        :x:         |                                                                                                                        |
|      [functional](#functional)      |         Utility          | :heavy_check_mark: |  [functional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=291953395)  |
|               future                |          Thread          |        :x:         |                                                                                                                        |
|               fstream               |       Input/Output       |        :x:         |                                                                                                                        |
|              ifstream               |       Input/Output       |        :x:         |                                                                                                                        |
|          initializer_list           |         Utility          |        :x:         |                                                                                                                        |
|               iomanip               |       Input/Output       |        :x:         |                                                                                                                        |
|             [ios](#ios)             |       Input/Output       | :heavy_check_mark: |     [ios](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)     |
|               iosfwd                |       Input/Output       |        :x:         |                                                                                                                        |
|              iostream               |       Input/Output       |        :x:         |                                                                                                                        |
|        [iterator](#iterator)        |         Iterator         | :heavy_check_mark: |  [iterator](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)   |
|               istream               |       Input/Output       |        :x:         |                                                                                                                        |
|                latch                |          Thread          |        :x:         |                                                                                                                        |
|          [limits](#limits)          | Utility / Numeric Limits | :heavy_check_mark: |   [limits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)    |
|                list                 |        Containers        |        :x:         |                                                                                                                        |
|               locale                |       Localization       |        :x:         |                                                                                                                        |
|          [linalg](#linalg)          |         Numeric          | :heavy_check_mark: |   [linalg](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1038174926)    |
|          [mdspan](#mdspan)          |        Containers        | :heavy_check_mark: |    [mdspan](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=713673184)    |
|          [memory](#memory)          | Utility / Dynamic Memory | :heavy_check_mark: |   [memory](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)    |
|           memory_resource           | Utility / Dynamic Memory |        :x:         |                                                                                                                        |
|           [mutex](#mutex)           |          Thread          | :heavy_check_mark: |    [mutex](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)    |
|             [new](#new)             | Utility / Dynamic Memory | :heavy_check_mark: |     [new](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)     |
|         [numbers](#numbers)         |         Numeric          | :heavy_check_mark: |   [numbers](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=641824361)    |
|         [numeric](#numeric)         |         Numeric          | :heavy_check_mark: |   [numeric](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1599843301)   |
|        [optional](#optional)        |         Utility          | :heavy_check_mark: |  [optional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1965816070)   |
|               ostream               |       Input/Output       |        :x:         |                                                                                                                        |
|                queue                |        Containers        |        :x:         |                                                          TODO                                                          |
|          [random](#random)          |         Numeric          | :heavy_check_mark: |   [random](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1617592580)    |
|          [ranges](#ranges)          |          Ranges          | :heavy_check_mark: |   [ranges](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1838971204)    |
|                regex                |   Regular Expressions    |        :x:         |                                                                                                                        |
|           [ratio](#ratio)           |         Numeric          | :heavy_check_mark: |    [ratio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1383686309)    |
|          scoped_allocator           | Utility / Dynamic Memory |        :x:         |                                                                                                                        |
|           [scope](#scope)           |         Utility          | :heavy_check_mark: |                                                                                                                        |
|              semaphore              |          Thread          |        :x:         |                                                                                                                        |
| [source_location](#source_location) |         Utility          | :heavy_check_mark: |                                                                                                                        |
|             [set](#set)             |        Containers        | :heavy_check_mark: |     [set](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=930086747)      |
|            shared_mutex             |          Thread          |        :x:         |                                                                                                                        |
|            [span](#span)            |        Containers        | :heavy_check_mark: |    [span](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1750377555)     |
|           [stack](#stack)           |        Containers        | :heavy_check_mark: |    [stack](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=385809287)     |
|             stack_trace             |         Utility          |        :x:         |                                                                                                                        |
|       [stdexcept](#stdexcept)       | Utility / Error Handling | :heavy_check_mark: |   [stdexcept](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing)    |
|              streambuf              |       Input/Output       |        :x:         |                                                                                                                        |
|          [string](#string)          |         Strings          | :heavy_check_mark: |    [string](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=43463000)     |
|     [string_view](#string_view)     |         Strings          | :heavy_check_mark: | [string_view](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1803550736) |
|             stop_token              |          Thread          |        :x:         |                                                                                                                        |
|               sstream               |       Input/Output       |        :x:         |                                                                                                                        |
|    [system_error](#system_error)    | Utility / Error Handling | :heavy_check_mark: | [system_error](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=635426347) |
|             sync_stream             |       Input/Output       |        :x:         |                                                                                                                        |
|               thread                |          Thread          |        :x:         |                                                                                                                        |
|           [tuple](#tuple)           |         Utility          | :heavy_check_mark: |    [tuple](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=857929646)     |
|             type_index              |         Utility          |        :x:         |                                                                                                                        |
|              type_info              |         Utility          |        :x:         |                                                                                                                        |
|     [type_traits](#type_traits)     |         Utility          | :heavy_check_mark: | [type_traits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1691010448) |
|            unordered_map            |        Containers        |        :x:         |                                                          TODO                                                          |
|            unordered_set            |        Containers        |        :x:         |                                                          TODO                                                          |
|         [utility](#utility)         |         Utility          | :heavy_check_mark: |   [utility](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1484976254)   |
|              valarray               |         Numeric          |        :x:         |                                                                                                                        |
|         [variant](#variant)         |         Utility          | :heavy_check_mark: |   [variant](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=503059518)    |
|          [vector](#vector)          |        Containers        | :heavy_check_mark: |   [vector](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1613833122)    |
|         [version](#version)         |         Utility          | :heavy_check_mark: |                                                                                                                        |
|         [warning](#warning)         |         Utility          | :heavy_check_mark: |                                                      Non-standard                                                      |

## Header Detail

### algorithm

- **Library:** Algorithms
- **Include:** [`etl/algorithm.hpp`](./include/etl/algorithm.hpp)
- **Example:** [algorithm.cpp](./examples/algorithm.cpp)
- **Implementation Progress:** [algorithm](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1451123716)
- **Changes:**
  - Implementations are optimize for code size. See [etl::search vs. libstdc++ (godbolt.org)](https://godbolt.org/z/dY9zPf8cs) as an example.
  - All overloads using an execution policy are not implemented.

### array

- **Library:** Containers
- **Include:** [`etl/array.hpp`](./include/etl/array.hpp)
- **Example:** [array.cpp](./examples/array.cpp)
- **Implementation Progress:** [array](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1320059600)
- **Changes:**
  - None

### bit

- **Library:** Numeric
- **Include:** [`etl/bit.hpp`](./include/etl/bit.hpp)
- **Example:** [bit.cpp](./examples/bit.cpp)
- **Implementation Progress:** [bit](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1927645890)
- **Changes:**
  - None

### bitset

- **Library:** Utility
- **Include:** [`etl/bitset.hpp`](./include/etl/bitset.hpp)
- **Example:** [bitset.cpp](./examples/bitset.cpp)
- **Implementation Progress:** [bitset](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=692946382)
- **Changes:**
  - TODO

### cassert

- **Library:** Utility / Error Handling
- **Include:** [`etl/cassert.hpp`](./include/etl/cassert.hpp)
- **Example:** [cassert.cpp](./examples/cassert.cpp)
- **Implementation Progress:** [cassert](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=460740183)
- **Changes:**
  - Added custom assertion macro `TETL_ASSERT`. The behavoir can be customized. The macro get's called every time an exceptional case has occurred inside the library. See the example file for more details.

### cctype

- **Library:** Strings
- **Include:** [`etl/cctype.hpp`](./include/etl/cctype.hpp)
- **Example:** TODO
- **Implementation Progress:** [cctype](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=522168028)
- **Changes:**
  - Locale independent

### cfloat

- **Library:** Utility / Numeric Limits
- **Include:** [`etl/cfloat.hpp`](./include/etl/cfloat.hpp)
- **Example:** TODO
- **Implementation Progress:** [cfloat](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1012838019)
- **Changes:**
  - None

### charconv

- **Library:** Strings
- **Include:** [`etl/charconv.hpp`](./include/etl/charconv.hpp)
- **Example:** TODO
- **Implementation Progress:** [charconv](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=345887816)
- **Changes:**
  - None

### chrono

- **Library:** Utility
- **Include:** [`etl/chrono.hpp`](./include/etl/chrono.hpp)
- **Example:** [chrono.cpp](./examples/chrono.cpp)
- **Implementation Progress:** [chrono](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1279150724)
- **Changes:**
  - No clocks are implemented. You have to provide your own, which must at least meet the requirements of [Clock](https://en.cppreference.com/w/cpp/named_req/Clock).

### climits

- **Library:** Utility / Numeric Limits
- **Include:** [`etl/climits.hpp`](./include/etl/climits.hpp)
- **Example:** TODO
- **Implementation Progress:** [climits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1904156895)
- **Changes:**
  - None

### cmath

- **Library:** Numeric
- **Include:** [`etl/cmath.hpp`](./include/etl/cmath.hpp)
- **Example:** TODO
- **Implementation Progress:** [cmath](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=868070087)
- **Changes:**
  - None

### compare

- **Library:** Utility
- **Include:** [`etl/compare.hpp`](./include/etl/compare.hpp)
- **Example:** TODO
- **Implementation Progress:** [compare](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1676133546)
- **Changes:**
  - None

### complex

- **Library:** Numeric
- **Include:** [`etl/complex.hpp`](./include/etl/complex.hpp)
- **Example:** TODO
- **Implementation Progress:** [complex](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1768885550)
- **Changes:**
  - None

### concepts

- **Library:** Concepts
- **Include:** [`etl/concepts.hpp`](./include/etl/concepts.hpp)
- **Example:** TODO
- **Implementation Progress:** [concepts](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=73781271)
- **Changes:**
  - None

### cstddef

- **Library:** Utility
- **Include:** [`etl/cstddef.hpp`](./include/etl/cstddef.hpp)
- **Example:** TODO
- **Implementation Progress:** [cstddef](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1660546405)
- **Changes:**
  - None

### cstdint

- **Library:** Utility / Numeric Limits
- **Include:** [`etl/cstdint.hpp`](./include/etl/cstdint.hpp)
- **Example:** TODO
- **Implementation Progress:** [cstdint](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2005735528)
- **Changes:**
  - None

### cstdio

- **Library:** Input/Output
- **Include:** [`etl/cstdio.hpp`](./include/etl/cstdio.hpp)
- **Example:** TODO
- **Implementation Progress:** [cstdio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1576270107)
- **Changes:**
  - TODO

### cstdlib

- **Library:** Utility
- **Include:** [`etl/cstdlib.hpp`](./include/etl/cstdlib.hpp)
- **Example:** TODO
- **Implementation Progress:** [cstdlib](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1705155517)
- **Changes:**
  - None

### cstring

- **Library:** Strings
- **Include:** [`etl/cstring.hpp`](./include/etl/cstring.hpp)
- **Example:** TODO
- **Implementation Progress:** [cstring](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1824871501)
- **Changes:**
  - TODO

### ctime

- **Library:** Utility
- **Include:** [`etl/ctime.hpp`](./include/etl/ctime.hpp)
- **Example:** TODO
- **Implementation Progress:** [ctime](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1082109762)
- **Changes:**
  - TODO

### cwchar

- **Library:** Strings
- **Include:** [`etl/cwchar.hpp`](./include/etl/cwchar.hpp)
- **Example:** TODO
- **Implementation Progress:** [cwchar](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1105944467)
- **Changes:**
  - None

### cwctype

- **Library:** Strings
- **Include:** [`etl/cwctype.hpp`](./include/etl/cwctype.hpp)
- **Example:** TODO
- **Implementation Progress:** [cwctype](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1740196036)
- **Changes:**
  - None

### exception

- **Library:** Error handling
- **Include:** [`etl/exception.hpp`](./include/etl/exception.hpp)
- **Example:** TODO
- **Implementation Progress:** [exception](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing)
- **Changes:**
  - TODO

### expected

- **Library:** Utility / Error Handling
- **Include:** [`etl/expected.hpp`](./include/etl/expected.hpp)
- **Example:** TODO
- **Implementation Progress:** [expected](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1624993362)
- **Changes:**
  - TODO

### flat_set

- **Library:** Container
- **Include:** [`etl/flat_set.hpp`](./include/etl/flat_set.hpp)
- **Example:** TODO
- **Implementation Progress:** [flat_set](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=291280131)
- **Changes:**
  - TODO

### flat_map

- **Library:** Container
- **Include:** [`etl/flat_map.hpp`](./include/etl/flat_map.hpp)
- **Example:** TODO
- **Implementation Progress:** [flat_map](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1047136935)
- **Changes:**
  - TODO

### format

- **Library:** Strings
- **Include:** [`etl/format.hpp`](./include/etl/format.hpp)
- **Example:** TODO
- **Implementation Progress:** [format](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=159875067)
- **Changes:**
  - WIP. Don't use.

### functional

- **Library:** Utility
- **Include:** [`etl/functional.hpp`](./include/etl/functional.hpp)
- **Example:** TODO
- **Implementation Progress:** [functional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=291953395)
- **Changes:**
  - TODO

### ios

- **Library:** Input/Output
- **Include:** [`etl/ios.hpp`](./include/etl/ios.hpp)
- **Example:** TODO
- **Implementation Progress:** [ios](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)
- **Changes:**
  - TODO

### iterator

- **Library:** Iterator
- **Include:** [`etl/iterator.hpp`](./include/etl/iterator.hpp)
- **Example:** TODO
- **Implementation Progress:** [iterator](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1722716093)
- **Changes:**
  - TODO

### limits

- **Library:** Utility / Numeric Limits
- **Include:** [`etl/limits.hpp`](./include/etl/limits.hpp)
- **Example:** TODO
- **Implementation Progress:** [limits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1966217100)
- **Changes:**
  - None

### linalg

- **Library:** Numeric
- **Include:** [`etl/linalg.hpp`](./include/etl/linalg.hpp)
- **Example:** TODO
- **Implementation Progress:** [linalg](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1038174926)
- **Changes:**
  - None

### mdspan

- **Library:** Containers
- **Include:** [`etl/mdspan.hpp`](./include/etl/mdspan.hpp)
- **Example:** TODO
- **Implementation Progress:** [mdspan](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=713673184)
- **Changes:**
  - None

### memory

- **Library:** Utility / Dynamic Memory
- **Include:** [`etl/memory.hpp`](./include/etl/memory.hpp)
- **Example:** [memory.cpp](./examples/memory.cpp)
- **Implementation Progress:** [memory](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1321444012)
- **Changes:**
  - Non-standard class templates `small_ptr` (compressed pointer) & `pointer_int_pair` (pointer + integer) are provided.

### mutex

- **Library:** Thread
- **Include:** [`etl/mutex.hpp`](./include/etl/mutex.hpp)
- **Example:** [mutex.cpp](./examples/mutex.cpp)
- **Implementation Progress:** [mutex](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=965791558)
- **Changes:**
  - Only RAII lock types are implemented. You have to provide a mutex type that at least meets the [BasicLockable](https://en.cppreference.com/w/cpp/named_req/BasicLockable) requirements.

### new

- **Library:** Utility / Dynamic Memory
- **Include:** [`etl/new.hpp`](./include/etl/new.hpp)
- **Example:** TODO
- **Implementation Progress:** [new](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1146466573)
- **Changes:**
  - None
  - If the standard `<new>` is availble it is used to define the global placement new functions to avoid ODR violations when mixing `std` & `etl` headers.

### numbers

- **Library:** Numeric
- **Include:** [`etl/numbers.hpp`](./include/etl/numbers.hpp)
- **Example:** TODO
- **Implementation Progress:** [numbers](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=641824361)
- **Changes:**
  - None

### numeric

- **Library:** Numeric
- **Include:** [`etl/numeric.hpp`](./include/etl/numeric.hpp)
- **Example:** [numeric.cpp](./examples/numeric.cpp)
- **Implementation Progress:** [numeric](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1599843301)
- **Changes:**
  - Implementations are optimize for code size. See [etl::search vs. libstdc++ (godbolt.org)](https://godbolt.org/z/dY9zPf8cs) as an example.
  - All overloads using an execution policy are not implemented.

### optional

- **Library:** Utility
- **Include:** [`etl/optional.hpp`](./include/etl/optional.hpp)
- **Example:** [optional.cpp](./examples/optional.cpp)
- **Implementation Progress:** [optional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1965816070)
- **Changes:**
  - TODO

### random

- **Library:** Random Number
- **Include:** [`etl/random.hpp`](./include/etl/random.hpp)
- **Example:** [random.cpp](./examples/random.cpp)
- **Implementation Progress:** [random](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1617592580)
- **Changes:**
  - Added `basic_xorshift32` and `basic_xorshift64` (Non-standard)

### ranges

- **Library:** Ranges
- **Include:** [`etl/ranges.hpp`](./include/etl/ranges.hpp)
- **Example:** TODO
- **Implementation Progress:** [ranges](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1838971204)
- **Changes:**
  - TODO

### ratio

- **Library:** Numeric
- **Include:** [`etl/ratio.hpp`](./include/etl/ratio.hpp)
- **Example:** [ratio.cpp](./examples/ratio.cpp)
- **Implementation Progress:** [ratio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1383686309)
- **Changes:**
  - None

### scope

- **Library:** Utility
- **Include:** [`etl/scope.hpp`](./include/etl/scope.hpp)
- **Example:** TODO
- **Implementation Progress:** TODO
- **Reference:** [en.cppreference.com/w/cpp/experimental/scope_exit](https://en.cppreference.com/w/cpp/experimental/scope_exit)
- **Changes:**
  - Based on [p0052r8](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p0052r8.pdf)
  - Only provides `scope_exit`

### source_location

- **Library:** Utility
- **Include:** [`etl/source_location.hpp`](./include/etl/source_location.hpp)
- **Example:** [source_location.cpp](./examples/source_location.cpp)
- **Implementation Progress:** TODO
- **Changes:**
  - None

### set

- **Library:** Containers
- **Include:** [`etl/set.hpp`](./include/etl/set.hpp)
- **Example:** [set.cpp](./examples/set.cpp)
- **Implementation Progress:** [set](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=930086747)
- **Changes:**
  - Renamed `set` to `static_set`. Fixed compile-time capacity.
  - If `is_trivial_v<T>`, then `is_trivially_copyable_v<static_set<T, Capacity>>`
  - If `is_trivial_v<T>`, then `is_trivially_destructible_v<static_set<T, Capacity>>`

### span

- **Library:** Containers
- **Include:** [`etl/span.hpp`](./include/etl/span.hpp)
- **Example:** TODO
- **Implementation Progress:** [span](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1750377555)

### stack

- **Library:** Containers
- **Include:** [`etl/stack.hpp`](./include/etl/stack.hpp)
- **Example:** TODO
- **Implementation Progress:** [stack](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=385809287)
- **Changes:**
  - None. Works with `static_vector`.

### stdexcept

- **Library:** Error handling
- **Include:** [`etl/stdexcept.hpp`](./include/etl/stdexcept.hpp)
- **Example:** TODO
- **Implementation Progress:** [stdexcept](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing)
- **Changes:**
  - TODO

### string

- **Library:** Strings
- **Include:** [`etl/string.hpp`](./include/etl/string.hpp)
- **Example:** [string.cpp](./examples/string.cpp)
- **Implementation Progress:** [string](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=43463000)
- **Changes:**
  - Only implemeted for type `char` at the moment.
  - Renamed `basic_string` to `basic_static_string`. Fixed compile-time capacity.

### string_view

- **Library:** Strings
- **Include:** [`etl/string_view.hpp`](./include/etl/string_view.hpp)
- **Example:** [string_view.cpp](./examples/string_view.cpp)
- **Implementation Progress:** [string_view](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1803550736)
- **Changes:**
  - None
  - Only implemeted for type `char` at the moment.

### system_error

- **Library:** Utility / Error Handling
- **Include:** [`etl/system_error.hpp`](./include/etl/system_error.hpp)
- **Example:** TODO
- **Implementation Progress:** [system_error](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=635426347)
- **Changes:**
  - Only provides `errc` enum and helper traits.

### tuple

- **Library:** Utility
- **Include:** [`etl/tuple.hpp`](./include/etl/tuple.hpp)
- **Example:** [tuple.cpp](./examples/tuple.cpp)
- **Implementation Progress:** [tuple](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=857929646)
- **Changes:**
  - Broken at the moment.

### type_traits

- **Library:** Utility
- **Include:** [`etl/type_traits.hpp`](./include/etl/type_traits.hpp)
- **Example:** [type_traits.cpp](./examples/type_traits.cpp)
- **Implementation Progress:** [type_traits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1691010448)
- **Changes:**
  - None

### utility

- **Library:** Utility
- **Include:** [`etl/utility.hpp`](./include/etl/utility.hpp)
- **Example:** [utility.cpp](./examples/utility.cpp)
- **Implementation Progress:** [utility](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1484976254)
- **Changes:**
  - None

### variant

- **Library:** Utility
- **Include:** [`etl/variant.hpp`](./include/etl/variant.hpp)
- **Example:** TODO
- **Implementation Progress:** [variant](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=503059518)
- **Changes:**
  - Broken at the moment.

### vector

- **Library:** Containers
- **Include:** [`etl/vector.hpp`](./include/etl/vector.hpp)
- **Example:** [vector.cpp](./examples/vector.cpp)
- **Implementation Progress:** [vector](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1613833122)
- **Changes:**
  - Renamed `vector` to `static_vector`. Fixed compile-time capacity.
  - Based on `P0843r3` and the reference implementation from [github.com/gnzlbg/static_vector](https://github.com/gnzlbg/static_vector).
  - If `is_trivial_v<T>`, then `is_trivially_copyable_v<static_vector<T, Capacity>>`
  - If `is_trivial_v<T>`, then `is_trivially_destructible_v<static_vector<T, Capacity>>`

### version

- **Library:** Utility
- **Include:** [`etl/version.hpp`](./include/etl/version.hpp)

Get access to all intrinsic macros & library version macro and constants. This header also include `<version>` from C++20 if it is available.

```cpp
#include "etl/version.hpp"

#include <stdio.h>

auto main() -> int
{
  puts(TETL_VERSION_STRING);  // Print current library version

  // Detect compiler
#if defined(TETL_MSVC)
  puts("msvc");
#if defined(TETL_GCC)
  puts("gcc");
#if defined(TETL_CLANG)
  puts("clang");
#else
  puts("other compiler");
#endif

  // Detect C++ standard
  if (etl::current_standard == language_standard::cpp_20) { puts("using C++20"); }
  if (etl::current_standard == language_standard::cpp_23) { puts("using C++23"); }

  return 0;
}
```

### warning

- **Library:** Utility
- **Include:** [`etl/warning.hpp`](./include/etl/warning.hpp)

```cpp
#include "etl/warning.hpp"

auto main(int argc, char** argv) -> int
{
  // Explicitly ignore unused arguments or variables.
  etl::ignore_unused(argc, argv);
  return 0;
}
```
