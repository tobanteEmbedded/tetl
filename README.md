# TAETL - Embedded Template Library

- [Status](#status)
  - [Hosted](#hosted)
  - [Freestanding](#freestanding)
- [Quick Start](#quick-start)
- [Design Goals](#design-goals)
- [Usage](#usage)
- [Project Integration](#project-integration)
  - [Command Line / Makefile](#command-line---makefile)
  - [CMake](#cmake)
  - [PlatformIO](#platformio)
- [Header Overview](#header-overview)
- [Header Detail](#header-detail)

It all started when I wanted to have a vector without dynamic memory. At that time I didn't know that projects like static_vector already existed. My actual goal has turned into a mammoth project. A standard library for microcontrollers and other embedded environments. The API is, as far as it is technically feasible, identical to the STL. All algorithms work identically, pair and friend are available and containers like set, map and vector are also implemented.

Here, however, the first clear differences already come to light. All containers work only with memory on the stack. This means that their size must be known at compile time. Furthermore I assume an environment in which exceptions and RTTI are deactivated. This results in the problem that not all members of a container can be implemented. Any function that returns a reference to a sequence element has the ability to throw exceptions in a normal hosted environment. If exceptions are disabled, this is not possible. For now, my solution to this problem is to delegate to the user. All functions return pointers instead. It is the caller's responsibility to check if the return value is null.

## Status

| **License**                                                                                                                 | **Issues**                                                                                                                     | **Code Coverage**                                                                                                            | **Clang-Tidy**                                                                                                                                                            | **Lines of Code**                                   |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) | [![GitHub issues](https://img.shields.io/github/issues/tobanteAudio/taetl.svg)](https://GitHub.com/tobanteAudio/taetl/issues/) | [![codecov](https://codecov.io/gh/tobanteAudio/taetl/branch/main/graph/badge.svg)](https://codecov.io/gh/tobanteAudio/taetl) | [![Clang-Tidy](https://github.com/tobanteAudio/taetl/actions/workflows/clang-tidy.yml/badge.svg)](https://github.com/tobanteAudio/taetl/actions/workflows/clang-tidy.yml) | [![](https://sloc.xyz/github/tobanteAudio/taetl)]() |

### Hosted

| **Compiler** |                                                                                       **C++17**                                                                                       |                                                                                       **C++20**                                                                                       |
| :----------: | :-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
|   **GCC**    |       [![GCC C++17](https://github.com/tobanteAudio/taetl/workflows/GCC%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22GCC+C%2B%2B17%22)       |       [![GCC C++20](https://github.com/tobanteAudio/taetl/workflows/GCC%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22GCC+C%2B%2B20%22)       |
|  **Clang**   |    [![Clang C++17](https://github.com/tobanteAudio/taetl/workflows/Clang%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22Clang+C%2B%2B17%22)    |    [![Clang C++20](https://github.com/tobanteAudio/taetl/workflows/Clang%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22Clang+C%2B%2B20%22)    |
|  **macOS**   |    [![macOS C++17](https://github.com/tobanteAudio/taetl/workflows/macOS%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22macOS+C%2B%2B17%22)    |    [![macOS C++20](https://github.com/tobanteAudio/taetl/workflows/macOS%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22macOS+C%2B%2B20%22)    |
| **Windows**  | [![Windows C++17](https://github.com/tobanteAudio/taetl/workflows/Windows%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22Windows+C%2B%2B17%22) | [![Windows C++20](https://github.com/tobanteAudio/taetl/workflows/Windows%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22Windows+C%2B%2B20%22) |

### Freestanding

| **Compiler** |                                                                                 **C++17**                                                                                 |                                                                                 **C++20**                                                                                 |
| :----------: | :-----------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| **AVR GCC**  | [![AVR C++17](https://github.com/tobanteAudio/taetl/workflows/AVR%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22AVR+C%2B%2B17%22) | [![AVR C++20](https://github.com/tobanteAudio/taetl/workflows/AVR%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22AVR+C%2B%2B20%22) |
| **ARM GCC**  | [![ARM C++17](https://github.com/tobanteAudio/taetl/workflows/ARM%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22ARM+C%2B%2B17%22) | [![ARM C++20](https://github.com/tobanteAudio/taetl/workflows/ARM%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22ARM+C%2B%2B20%22) |

## Quick Start

```sh
git clone https://github.com/tobanteAudio/taetl.git
```

- [Implementation Progress (Spreadsheet)](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing)
- [API Reference](https://tobanteaudio.github.io/taetl/index.html)
- [Examples](https://github.com/tobanteAudio/taetl/tree/main/examples)

## Design Goals

- 100% portable (no STL headers required, minimum of C headers)
- Header only
- C++17
- Similar api to the STL
- No dynamic memory
- `constexpr` all the things
- Easy desktop development (cmake)
  - Stubs for external dependencies (FreeRTOS)
- Experimental headers
  - Strong types
  - Networking (buffers, ntoh, ...)
  - FreeRTOS Abstraction
  - STM32 HAL
  - DSP DSL via Template Meta Programming

## Usage

For detailed examples look at the [examples](./examples) subdirectory or the test files in [tests](./tests).

## Project Integration

The following steps explain how to add `etl` to your project. Embedded or desktop.

```sh
cd path/to/your/project
mkdir 3rd_party
git submodule add https://github.com/tobanteAudio/taetl.git 3rd_party/taetl
```

### Command Line / Makefile

```make
CXXFLAGS += -I3rd_party/taetl
```

### CMake

Add `taetl` as a git submodule, then add these lines to your `CMakeLists.txt`:

```cmake
add_subdirectory(3rd_party/taetl EXCLUDE_FROM_ALL)
target_link_libraries(${YOUR_TARGET} tobanteAudio::etl)
```

### PlatformIO

Add `taetl` as a git submodule, then add these lines to your `platformio.ini`:

```ini
[env:yourenv]
build_unflags = -std=gnu++11
build_flags = -std=gnu++17 -Wno-register -I 3rd_party/taetl
```

## Header Overview

|            Header             |         Library          |       Status       |                   Source                   |                     Tests                     |     Comments      |
| :---------------------------: | :----------------------: | :----------------: | :----------------------------------------: | :-------------------------------------------: | :---------------: |
|    [algorithm](#algorithm)    |        Algorithms        | :heavy_check_mark: |    [algorithm.hpp](./etl/algorithm.hpp)    |    [algorithm](./tests/test_algorithm.cpp)    |                   |
|            [any]()            |         Utility          |        :x:         |                                            |                                               |                   |
|        [array](#array)        |        Containers        | :heavy_check_mark: |        [array.hpp](./etl/array.hpp)        |        [array](./tests/test_array.cpp)        |                   |
|          [atomic]()           |          Atomic          |        :x:         |                                            |                                               |                   |
|          [barrier]()          |          Thread          |        :x:         |                                            |                                               |                   |
|          [bit](#bit)          |         Numeric          | :heavy_check_mark: |          [bit.hpp](./etl/bit.hpp)          |          [bit](./tests/test_bit.cpp)          |                   |
|       [bitset](#bitset)       |         Utility          | :heavy_check_mark: |       [bitset.hpp](./etl/bitset.hpp)       |       [bitset](./tests/test_bitset.cpp)       |                   |
|      [cassert](#cassert)      | Utility / Error Handling | :heavy_check_mark: |      [cassert.hpp](./etl/cassert.hpp)      |      [cassert](./tests/test_cassert.cpp)      |                   |
|       [cctype](#cctype)       |         Strings          | :heavy_check_mark: |       [cctype.hpp](./etl/cctype.hpp)       |       [cctype](./tests/test_cctype.cpp)       |                   |
|          [cerrno]()           | Utility / Error Handling |        :x:         |                                            |                                               |                   |
|           [cfenv]()           |         Numeric          |        :x:         |                                            |                                               |                   |
|       [cfloat](#cfloat)       | Utility / Numeric Limits | :heavy_check_mark: |       [cfloat.hpp](./etl/cfloat.hpp)       |       [cfloat](./tests/test_cfloat.cpp)       |                   |
|     [charconv](#charconv)     |         Strings          | :heavy_check_mark: |     [charconv.hpp](./etl/charconv.hpp)     |     [charconv](./tests/test_charconv.cpp)     |                   |
|       [chrono](#chrono)       |         Utility          | :heavy_check_mark: |       [chrono.hpp](./etl/chrono.hpp)       |       [chrono](./tests/test_chrono.cpp)       |                   |
|         [cinttypes]()         | Utility / Numeric Limits |        :x:         |                                            |                                               |       TODO        |
|      [climits](#climits)      | Utility / Numeric Limits | :heavy_check_mark: |      [climits.hpp](./etl/climits.hpp)      |      [climits](./tests/test_climits.cpp)      |                   |
|          [clocale]()          |       Localization       |        :x:         |                                            |                                               |                   |
|        [cmath](#cmath)        |         Numeric          | :heavy_check_mark: |        [cmath.hpp](./etl/cmath.hpp)        |        [cmath](./tests/test_cmath.cpp)        |                   |
|          [compare]()          |         Utility          |        :x:         |                                            |                                               |       TODO        |
|          [complex]()          |         Numeric          |        :x:         |                                            |                                               |                   |
|     [concepts](#concepts)     |         Concepts         | :heavy_check_mark: |     [concepts.hpp](./etl/concepts.hpp)     |     [concepts](./tests/test_concepts.cpp)     |                   |
|    [condition_variable]()     |          Thread          |        :x:         |                                            |                                               |                   |
|         [coroutine]()         |        Coroutines        |        :x:         |                                            |                                               |                   |
|         [crtp](#crtp)         |         Utility          | :heavy_check_mark: |         [crtp.hpp](./etl/crtp.hpp)         |         [crtp](./tests/test_crtp.cpp)         |   Not standard.   |
|          [csetjmp]()          |         Utility          |        :x:         |                                            |                                               |                   |
|          [csignal]()          |         Utility          |        :x:         |                                            |                                               |                   |
|          [cstdarg]()          |         Utility          |        :x:         |                                            |                                               |                   |
|      [cstddef](#cstddef)      |         Utility          | :heavy_check_mark: |      [cstddef.hpp](./etl/cstddef.hpp)      |      [cstddef](./tests/test_cstddef.cpp)      |                   |
|      [cstdint](#cstdint)      | Utility / Numeric Limits | :heavy_check_mark: |      [cstdint.hpp](./etl/cstdint.hpp)      |      [cstdint](./tests/test_cstdint.cpp)      |                   |
|       [cstdio](#cstdio)       |       Input/Output       | :heavy_check_mark: |       [cstdio.hpp](./etl/cstdio.hpp)       |       [cstdio](./tests/test_cstdio.cpp)       |                   |
|      [cstdlib](#cstdlib)      |         Utility          | :heavy_check_mark: |      [cstdlib.hpp](./etl/cstdlib.hpp)      |      [cstdlib](./tests/test_cstdlib.cpp)      |                   |
|      [cstring](#cstring)      |         Strings          | :heavy_check_mark: |      [cstring.hpp](./etl/cstring.hpp)      |      [cstring](./tests/test_cstring.cpp)      |                   |
|        [ctime](#ctime)        |         Utility          | :heavy_check_mark: |        [ctime.hpp](./etl/ctime.hpp)        |        [ctime](./tests/test_ctime.cpp)        |                   |
|          [cuchar]()           |         Strings          |        :x:         |                                            |                                               |                   |
|          [cwchar]()           |         Strings          |        :x:         |                                            |                                               |                   |
|          [cwctype]()          |         Strings          |        :x:         |                                            |                                               |                   |
|           [deque]()           |        Containers        |        :x:         |                                            |                                               |       TODO        |
|         [exception]()         | Utility / Error Handling |        :x:         |                                            |                                               |                   |
|         [execution]()         |        Algorithms        |        :x:         |                                            |                                               |       TODO        |
|     [expected](#expected)     | Utility / Error Handling | :heavy_check_mark: |     [expected.hpp](./etl/expected.hpp)     |     [expected](./tests/test_expected.cpp)     | Not standard yet. |
|        [filesystem]()         |        Filesystem        |        :x:         |                                            |                                               |                   |
|       [format](#format)       |         Strings          | :heavy_check_mark: |       [format.hpp](./etl/format.hpp)       |       [format](./tests/test_format.cpp)       |                   |
|       [forward_list]()        |        Containers        |        :x:         |                                            |                                               |                   |
|   [functional](#functional)   |         Utility          | :heavy_check_mark: |   [functional.hpp](./etl/functional.hpp)   |   [functional](./tests/test_functional.cpp)   |                   |
|          [future]()           |          Thread          |        :x:         |                                            |                                               |                   |
|          [fstream]()          |       Input/Output       |        :x:         |                                            |                                               |                   |
|         [ifstream]()          |       Input/Output       |        :x:         |                                            |                                               |                   |
|     [initializer_list]()      |                          |        :x:         |                                            |                                               |                   |
|          [iomanip]()          |       Input/Output       |        :x:         |                                            |                                               |                   |
|          [ios](#ios)          |       Input/Output       | :heavy_check_mark: |          [ios.hpp](./etl/ios.hpp)          |          [ios](./tests/test_ios.cpp)          |                   |
|          [iosfwd]()           |       Input/Output       |        :x:         |                                            |                                               |                   |
|         [iostream]()          |       Input/Output       |        :x:         |                                            |                                               |                   |
|     [iterator](#iterator)     |         Iterator         | :heavy_check_mark: |     [iterator.hpp](./etl/iterator.hpp)     |     [iterator](./tests/test_iterator.cpp)     |                   |
|          [istream]()          |       Input/Output       |        :x:         |                                            |                                               |                   |
|           [latch]()           |          Thread          |        :x:         |                                            |                                               |                   |
|       [limits](#limits)       | Utility / Numeric Limits | :heavy_check_mark: |       [limits.hpp](./etl/limits.hpp)       |       [limits](./tests/test_limits.cpp)       |                   |
|           [list]()            |        Containers        |        :x:         |                                            |                                               |                   |
|          [locale]()           |       Localization       |        :x:         |                                            |                                               |                   |
|          [map](#map)          |        Containers        | :heavy_check_mark: |          [map.hpp](./etl/map.hpp)          |          [map](./tests/test_map.cpp)          |                   |
|       [memory](#memory)       | Utility / Dynamic Memory | :heavy_check_mark: |       [memory.hpp](./etl/memory.hpp)       |       [memory](./tests/test_memory.cpp)       |                   |
|      [memory_resource]()      | Utility / Dynamic Memory |        :x:         |                                            |                                               |                   |
|        [mutex](#mutex)        |      Thread Support      | :heavy_check_mark: |        [mutex.hpp](./etl/mutex.hpp)        |        [mutex](./tests/test_mutex.cpp)        |                   |
|          [new](#new)          | Utility / Dynamic Memory | :heavy_check_mark: |          [new.hpp](./etl/new.hpp)          |          [new](./tests/test_new.cpp)          |                   |
|      [numbers](#numbers)      |         Numeric          | :heavy_check_mark: |      [numbers.hpp](./etl/numbers.hpp)      |      [numbers](./tests/test_numbers.cpp)      |                   |
|      [numeric](#numeric)      |         Numeric          | :heavy_check_mark: |      [numeric.hpp](./etl/numeric.hpp)      |      [numeric](./tests/test_numeric.cpp)      |                   |
|     [optional](#optional)     |         Utility          | :heavy_check_mark: |     [optional.hpp](./etl/optional.hpp)     |     [optional](./tests/test_optional.cpp)     |                   |
|          [ostream]()          |       Input/Output       |        :x:         |                                            |                                               |                   |
|           [queue]()           |        Containers        |        :x:         |                                            |                                               |       TODO        |
|          [random]()           |         Numeric          |        :x:         |                                            |                                               |                   |
|          [ranges]()           |          Ranges          |        :x:         |                                            |                                               |       TODO        |
|           [regex]()           |   Regular Expressions    |        :x:         |                                            |                                               |                   |
|        [ratio](#ratio)        |         Numeric          | :heavy_check_mark: |        [ratio.hpp](./etl/ratio.hpp)        |        [ratio](./tests/test_ratio.cpp)        |                   |
|     [scoped_allocator]()      | Utility / Dynamic Memory |        :x:         |                                            |                                               |                   |
|  [scope_guard](#scope_guard)  |         Utility          | :heavy_check_mark: |  [scope_guard.hpp](./etl/scope_guard.hpp)  |  [scope_guard](./tests/test_scope_guard.cpp)  | Not standard yet. |
|         [semaphore]()         |          Thread          |        :x:         |                                            |                                               |                   |
|      [source_location]()      |         Utility          |        :x:         |                                            |                                               |                   |
|          [set](#set)          |        Containers        | :heavy_check_mark: |          [set.hpp](./etl/set.hpp)          |          [set](./tests/test_set.cpp)          |                   |
|       [shared_mutex]()        |          Thread          |        :x:         |                                            |                                               |                   |
|         [span](#span)         |        Containers        | :heavy_check_mark: |         [span.hpp](./etl/span.hpp)         |         [span](./tests/test_span.cpp)         |                   |
|        [stack](#stack)        |        Containers        | :heavy_check_mark: |        [stack.hpp](./etl/stack.hpp)        |        [stack](./tests/test_stack.cpp)        |                   |
|        [stack_trace]()        |         Utility          |        :x:         |                                            |                                               |                   |
|         [stdexcept]()         | Utility / Error Handling |        :x:         |                                            |                                               |                   |
|         [streambuf]()         |       Input/Output       |        :x:         |                                            |                                               |                   |
|       [string](#string)       |         Strings          | :heavy_check_mark: |       [string.hpp](./etl/string.hpp)       |       [string](./tests/test_string.cpp)       |                   |
|  [string_view](#string_view)  |         Strings          | :heavy_check_mark: |  [string_view.hpp](./etl/string_view.hpp)  |  [string_view](./tests/test_string_view.cpp)  |                   |
|        [stop_token]()         |          Thread          |        :x:         |                                            |                                               |                   |
|          [sstream]()          |       Input/Output       |        :x:         |                                            |                                               |                   |
| [system_error](#system_error) | Utility / Error Handling | :heavy_check_mark: | [system_error.hpp](./etl/system_error.hpp) | [system_error](./tests/test_system_error.cpp) |                   |
|        [sync_stream]()        |       Input/Output       |        :x:         |                                            |                                               |                   |
|          [thread]()           |          Thread          |        :x:         |                                            |                                               |                   |
|        [tuple](#tuple)        |         Utility          | :heavy_check_mark: |        [tuple.hpp](./etl/tuple.hpp)        |        [tuple](./tests/test_tuple.cpp)        |                   |
|        [type_index]()         |         Utility          |        :x:         |                                            |                                               |                   |
|         [type_info]()         |         Utility          |        :x:         |                                            |                                               |                   |
|  [type_traits](#type_traits)  |         Utility          | :heavy_check_mark: |  [type_traits.hpp](./etl/type_traits.hpp)  |  [type_traits](./tests/test_type_traits.cpp)  |                   |
|       [unordered_map]()       |        Containers        |        :x:         |                                            |                                               |       TODO        |
|       [unordered_set]()       |        Containers        |        :x:         |                                            |                                               |       TODO        |
|      [utility](#utility)      |         Utility          | :heavy_check_mark: |      [utility.hpp](./etl/utility.hpp)      |      [utility](./tests/test_utility.cpp)      |                   |
|         [valarray]()          |         Numeric          |        :x:         |                                            |                                               |                   |
|      [variant](#variant)      |         Utility          | :heavy_check_mark: |      [variant.hpp](./etl/variant.hpp)      |      [variant](./tests/test_variant.cpp)      |                   |
|       [vector](#vector)       |        Containers        | :heavy_check_mark: |       [vector.hpp](./etl/vector.hpp)       |       [vector](./tests/test_vector.cpp)       |                   |
|      [version](#version)      |         Utility          | :heavy_check_mark: |      [version.hpp](./etl/version.hpp)      |      [version](./tests/test_version.cpp)      |                   |
|      [warning](#warning)      |         Utility          | :heavy_check_mark: |      [warning.hpp](./etl/warning.hpp)      |      [warning](./tests/test_warning.cpp)      |   Not standard.   |

## Header Detail

### algorithm

### array

### bit

### bitset

### cassert

### cctype

### cfloat

### charconv

### chrono

### climits

### cmath

### concepts

### crtp

### cstddef

### cstdint

### cstdio

### cstdlib

### cstring

### ctime

### expected

### format

### functional

### ios

### iterator

### limits

### map

### memory

### mutex

### new

### numbers

### numeric

### optional

### ratio

### scope_guard

### set

### span

### stack

### string

### string_view

### system_error

### tuple

### type_traits

### utility

### variant

### vector

### version

### warning
