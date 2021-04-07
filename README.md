# TAETL - Embedded Template **Library**

- [Quick Start](#quick-start)
- [Design Goals](#design-goals)
- [Usage](#usage)
- [Status](#status)
  - [Hosted](#hosted)
  - [Freestanding](#freestanding)
- [Project Integration](#project-integration)
  - [Command Line / Makefile](#command-line---makefile)
  - [CMake](#cmake)
  - [PlatformIO](#platformio)
- [Header Overview](#header-overview)
- [Header Detail](#header-detail)

It all started when I wanted to have a vector without dynamic memory. At that time I didn't know that projects like
static_vector already existed. My actual goal has turned into a mammoth project. A standard library for microcontrollers
and other embedded environments. The API is, as far as it is technically feasible, identical to the STL. All algorithms
work identically, pair and friend are available and containers like set, map and vector are also implemented.

Here, however, the first clear differences already come to light. All containers work only with memory on the stack.
This means that their size must be known at compile time. Furthermore I assume an environment in which exceptions and
RTTI are deactivated. This results in the problem that not all members of a container can be implemented. Any function
that returns a reference to a sequence element has the ability to throw exceptions in a normal hosted environment. If
exceptions are disabled, this is not possible. For now, my solution to this problem is to delegate to the user. All
functions return pointers instead. It is the caller's responsibility to check if the return value is null.

## Quick Start

```sh
git clone https://github.com/tobanteAudio/taetl.git
```

- [Implementation Progress (Spreadsheet)](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing)
- [API Reference](https://tobanteaudio.github.io/taetl/index.html)
- [**Example**s](https://github.com/tobanteAudio/taetl/tree/main/examples)

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

## Status

| **License**                                                                                                                 | **Issues**                                                                                                                     | **Code Coverage**                                                                                                            | **Clang-Tidy**                                                                                                                                                            | **Lines of Code**                                |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) | [![GitHub issues](https://img.shields.io/github/issues/tobanteAudio/taetl.svg)](https://GitHub.com/tobanteAudio/taetl/issues/) | [![codecov](https://codecov.io/gh/tobanteAudio/taetl/branch/main/graph/badge.svg)](https://codecov.io/gh/tobanteAudio/taetl) | [![Clang-Tidy](https://github.com/tobanteAudio/taetl/actions/workflows/clang-tidy.yml/badge.svg)](https://github.com/tobanteAudio/taetl/actions/workflows/clang-tidy.yml) | [![](https://sloc.xyz/github/tobanteAudio/taetl) |

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

|          **Header**           |       **Library**        |     **Status**     |   **Comments**    |
| :---------------------------: | :----------------------: | :----------------: | :---------------: |
|    [algorithm](#algorithm)    |        Algorithms        | :heavy_check_mark: |                   |
|              any              |         Utility          |        :x:         |                   |
|        [array](#array)        |        Containers        | :heavy_check_mark: |                   |
|            atomic             |          Atomic          |        :x:         |                   |
|            barrier            |          Thread          |        :x:         |                   |
|          [bit](#bit)          |         Numeric          | :heavy_check_mark: |                   |
|       [bitset](#bitset)       |         Utility          | :heavy_check_mark: |                   |
|      [cassert](#cassert)      | Utility / Error Handling | :heavy_check_mark: |                   |
|       [cctype](#cctype)       |         Strings          | :heavy_check_mark: |                   |
|            cerrno             | Utility / Error Handling |        :x:         |                   |
|             cfenv             |         Numeric          |        :x:         |       TODO        |
|       [cfloat](#cfloat)       | Utility / Numeric Limits | :heavy_check_mark: |                   |
|     [charconv](#charconv)     |         Strings          | :heavy_check_mark: |                   |
|       [chrono](#chrono)       |         Utility          | :heavy_check_mark: |                   |
|           cinttypes           | Utility / Numeric Limits |        :x:         |       TODO        |
|      [climits](#climits)      | Utility / Numeric Limits | :heavy_check_mark: |                   |
|            clocale            |       Localization       |        :x:         |                   |
|        [cmath](#cmath)        |         Numeric          | :heavy_check_mark: |                   |
|            compare            |         Utility          |        :x:         |       TODO        |
|            complex            |         Numeric          |        :x:         |       TODO        |
|     [concepts](#concepts)     |         Concepts         | :heavy_check_mark: |                   |
|      condition_variable       |          Thread          |        :x:         |                   |
|           coroutine           |        Coroutines        |        :x:         |                   |
|         [crtp](#crtp)         |         Utility          | :heavy_check_mark: |   Not standard.   |
|            csetjmp            |         Utility          |        :x:         |                   |
|            csignal            |         Utility          |        :x:         |                   |
|      [cstdarg](#cstdarg)      |         Utility          | :heavy_check_mark: |                   |
|      [cstddef](#cstddef)      |         Utility          | :heavy_check_mark: |                   |
|      [cstdint](#cstdint)      | Utility / Numeric Limits | :heavy_check_mark: |                   |
|       [cstdio](#cstdio)       |       Input/Output       | :heavy_check_mark: |                   |
|      [cstdlib](#cstdlib)      |         Utility          | :heavy_check_mark: |                   |
|      [cstring](#cstring)      |         Strings          | :heavy_check_mark: |                   |
|        [ctime](#ctime)        |         Utility          | :heavy_check_mark: |                   |
|            cuchar             |         Strings          |        :x:         |                   |
|            cwchar             |         Strings          |        :x:         |                   |
|            cwctype            |         Strings          |        :x:         |                   |
|             deque             |        Containers        |        :x:         |       TODO        |
|           exception           | Utility / Error Handling |        :x:         |                   |
|           execution           |        Algorithms        |        :x:         |       TODO        |
|     [expected](#expected)     | Utility / Error Handling | :heavy_check_mark: | Not standard yet. |
|          filesystem           |        Filesystem        |        :x:         |                   |
|       [format](#format)       |         Strings          | :heavy_check_mark: |                   |
|         forward_list          |        Containers        |        :x:         |                   |
|   [functional](#functional)   |         Utility          | :heavy_check_mark: |                   |
|            future             |          Thread          |        :x:         |                   |
|            fstream            |       Input/Output       |        :x:         |                   |
|           ifstream            |       Input/Output       |        :x:         |                   |
|       initializer_list        |                          |        :x:         |                   |
|            iomanip            |       Input/Output       |        :x:         |                   |
|          [ios](#ios)          |       Input/Output       | :heavy_check_mark: |                   |
|            iosfwd             |       Input/Output       |        :x:         |                   |
|           iostream            |       Input/Output       |        :x:         |                   |
|     [iterator](#iterator)     |         Iterator         | :heavy_check_mark: |                   |
|            istream            |       Input/Output       |        :x:         |                   |
|             latch             |          Thread          |        :x:         |                   |
|       [limits](#limits)       | Utility / Numeric Limits | :heavy_check_mark: |                   |
|             list              |        Containers        |        :x:         |                   |
|            locale             |       Localization       |        :x:         |                   |
|          [map](#map)          |        Containers        | :heavy_check_mark: |                   |
|       [memory](#memory)       | Utility / Dynamic Memory | :heavy_check_mark: |                   |
|        memory_resource        | Utility / Dynamic Memory |        :x:         |                   |
|        [mutex](#mutex)        |      Thread Support      | :heavy_check_mark: |                   |
|          [new](#new)          | Utility / Dynamic Memory | :heavy_check_mark: |                   |
|      [numbers](#numbers)      |         Numeric          | :heavy_check_mark: |                   |
|      [numeric](#numeric)      |         Numeric          | :heavy_check_mark: |                   |
|     [optional](#optional)     |         Utility          | :heavy_check_mark: |                   |
|            ostream            |       Input/Output       |        :x:         |                   |
|             queue             |        Containers        |        :x:         |       TODO        |
|            random             |         Numeric          |        :x:         |                   |
|            ranges             |          Ranges          |        :x:         |       TODO        |
|             regex             |   Regular Expressions    |        :x:         |                   |
|        [ratio](#ratio)        |         Numeric          | :heavy_check_mark: |                   |
|       scoped_allocator        | Utility / Dynamic Memory |        :x:         |                   |
|  [scope_guard](#scope_guard)  |         Utility          | :heavy_check_mark: | Not standard yet. |
|           semaphore           |          Thread          |        :x:         |                   |
|        source_location        |         Utility          |        :x:         |                   |
|          [set](#set)          |        Containers        | :heavy_check_mark: |                   |
|         shared_mutex          |          Thread          |        :x:         |                   |
|         [span](#span)         |        Containers        | :heavy_check_mark: |                   |
|        [stack](#stack)        |        Containers        | :heavy_check_mark: |                   |
|          stack_trace          |         Utility          |        :x:         |                   |
|           stdexcept           | Utility / Error Handling |        :x:         |                   |
|           streambuf           |       Input/Output       |        :x:         |                   |
|       [string](#string)       |         Strings          | :heavy_check_mark: |                   |
|  [string_view](#string_view)  |         Strings          | :heavy_check_mark: |                   |
|          stop_token           |          Thread          |        :x:         |                   |
|            sstream            |       Input/Output       |        :x:         |                   |
| [system_error](#system_error) | Utility / Error Handling | :heavy_check_mark: |                   |
|          sync_stream          |       Input/Output       |        :x:         |                   |
|            thread             |          Thread          |        :x:         |                   |
|        [tuple](#tuple)        |         Utility          | :heavy_check_mark: |                   |
|          type_index           |         Utility          |        :x:         |                   |
|           type_info           |         Utility          |        :x:         |                   |
|  [type_traits](#type_traits)  |         Utility          | :heavy_check_mark: |                   |
|         unordered_map         |        Containers        |        :x:         |       TODO        |
|         unordered_set         |        Containers        |        :x:         |       TODO        |
|      [utility](#utility)      |         Utility          | :heavy_check_mark: |                   |
|           valarray            |         Numeric          |        :x:         |                   |
|      [variant](#variant)      |         Utility          | :heavy_check_mark: |                   |
|       [vector](#vector)       |        Containers        | :heavy_check_mark: |                   |
|      [version](#version)      |         Utility          | :heavy_check_mark: |                   |
|      [warning](#warning)      |         Utility          | :heavy_check_mark: |   Not standard.   |

## Header Detail

### algorithm

| **Library** |              **Source**              |                    **Tests**                     |                **Example**                |                        **cppreference**                         |
| :---------: | :----------------------------------: | :----------------------------------------------: | :---------------------------------------: | :-------------------------------------------------------------: |
| Algorithms  | [algorithm.hpp](./etl/algorithm.hpp) | [test_algorithm.cpp](./tests/test_algorithm.cpp) | [algorithm.cpp](./examples/algorithm.cpp) | [algorithm](https://en.cppreference.com/w/cpp/header/algorithm) |

#### Changes

- Implementations are optimize for code size.
- All overloads using an execution policy are not implemented.

### array

| **Library** |          **Source**          |                **Tests**                 |            **Example**            |                    **cppreference**                     |
| :---------: | :--------------------------: | :--------------------------------------: | :-------------------------------: | :-----------------------------------------------------: |
| Containers  | [array.hpp](./etl/array.hpp) | [test_array.cpp](./tests/test_array.cpp) | [array.cpp](./examples/array.cpp) | [array](https://en.cppreference.com/w/cpp/header/array) |

### bit

| **Library** |        **Source**        |              **Tests**               | **Example** |                  **cppreference**                   |
| :---------: | :----------------------: | :----------------------------------: | :---------: | :-------------------------------------------------: |
|   Numeric   | [bit.hpp](./etl/bit.hpp) | [test_bit.cpp](./tests/test_bit.cpp) |    TODO     | [bit](https://en.cppreference.com/w/cpp/header/bit) |

### bitset

| **Library** |           **Source**           |                 **Tests**                  |             **Example**             |                     **cppreference**                      |
| :---------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :-------------------------------------------------------: |
|   Utility   | [bitset.hpp](./etl/bitset.hpp) | [test_bitset.cpp](./tests/test_bitset.cpp) | [bitset.cpp](./examples/bitset.cpp) | [bitset](https://en.cppreference.com/w/cpp/header/bitset) |

### cassert

|       **Library**        |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :----------------------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
| Utility / Error Handling | [cassert.hpp](./etl/cassert.hpp) | [test_cassert.cpp](./tests/test_cassert.cpp) |    TODO     | [cassert](https://en.cppreference.com/w/cpp/header/cassert) |

### cctype

| **Library** |           **Source**           |                 **Tests**                  | **Example** |                     **cppreference**                      |
| :---------: | :----------------------------: | :----------------------------------------: | :---------: | :-------------------------------------------------------: |
| Containers  | [cctype.hpp](./etl/cctype.hpp) | [test_cctype.cpp](./tests/test_cctype.cpp) |    TODO     | [cctype](https://en.cppreference.com/w/cpp/header/cctype) |

### cfloat

| **Library** |           **Source**           |                 **Tests**                  | **Example** |                     **cppreference**                      |
| :---------: | :----------------------------: | :----------------------------------------: | :---------: | :-------------------------------------------------------: |
| Containers  | [cfloat.hpp](./etl/cfloat.hpp) | [test_cfloat.cpp](./tests/test_cfloat.cpp) |    TODO     | [cfloat](https://en.cppreference.com/w/cpp/header/cfloat) |

### charconv

| **Library** |             **Source**             |                   **Tests**                    | **Example** |                       **cppreference**                        |
| :---------: | :--------------------------------: | :--------------------------------------------: | :---------: | :-----------------------------------------------------------: |
| Containers  | [charconv.hpp](./etl/charconv.hpp) | [test_charconv.cpp](./tests/test_charconv.cpp) |    TODO     | [charconv](https://en.cppreference.com/w/cpp/header/charconv) |

### chrono

| **Library** |           **Source**           |                 **Tests**                  |             **Example**             |                     **cppreference**                      |
| :---------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :-------------------------------------------------------: |
| Containers  | [chrono.hpp](./etl/chrono.hpp) | [test_chrono.cpp](./tests/test_chrono.cpp) | [chrono.cpp](./examples/chrono.cpp) | [chrono](https://en.cppreference.com/w/cpp/header/chrono) |

### climits

|       **Library**        |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :----------------------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
| Utility / Numeric Limits | [climits.hpp](./etl/climits.hpp) | [test_climits.cpp](./tests/test_climits.cpp) |    TODO     | [climits](https://en.cppreference.com/w/cpp/header/climits) |

### cmath

| **Library** |          **Source**          |                **Tests**                 | **Example** |                    **cppreference**                     |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :-----------------------------------------------------: |
|   Numeric   | [cmath.hpp](./etl/cmath.hpp) | [test_cmath.cpp](./tests/test_cmath.cpp) |    TODO     | [cmath](https://en.cppreference.com/w/cpp/header/cmath) |

### concepts

| **Library** |             **Source**             |                   **Tests**                    | **Example** |                       **cppreference**                        |
| :---------: | :--------------------------------: | :--------------------------------------------: | :---------: | :-----------------------------------------------------------: |
|  Concepts   | [concepts.hpp](./etl/concepts.hpp) | [test_concepts.cpp](./tests/test_concepts.cpp) |    TODO     | [concepts](https://en.cppreference.com/w/cpp/header/concepts) |

### crtp

| **Library** |         **Source**         |               **Tests**                | **Example** | cppreference |
| :---------: | :------------------------: | :------------------------------------: | :---------: | :----------: |
| Containers  | [crtp.hpp](./etl/crtp.hpp) | [test_crtp.cpp](./tests/test_crtp.cpp) |    TODO     |              |

### cstdarg

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
|   Utility   | [cstdarg.hpp](./etl/cstdarg.hpp) | [test_cstdarg.cpp](./tests/test_cstdarg.cpp) |    TODO     | [cstdarg](https://en.cppreference.com/w/cpp/header/cstdarg) |

### cstddef

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
|   Utility   | [cstddef.hpp](./etl/cstddef.hpp) | [test_cstddef.cpp](./tests/test_cstddef.cpp) |    TODO     | [cstddef](https://en.cppreference.com/w/cpp/header/cstddef) |

### cstdint

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
|   Utility   | [cstdint.hpp](./etl/cstdint.hpp) | [test_cstdint.cpp](./tests/test_cstdint.cpp) |    TODO     | [cstdint](https://en.cppreference.com/w/cpp/header/cstdint) |

### cstdio

| **Library** |           **Source**           |                 **Tests**                  | **Example** |                     **cppreference**                      |
| :---------: | :----------------------------: | :----------------------------------------: | :---------: | :-------------------------------------------------------: |
| Containers  | [cstdio.hpp](./etl/cstdio.hpp) | [test_cstdio.cpp](./tests/test_cstdio.cpp) |    TODO     | [cstdio](https://en.cppreference.com/w/cpp/header/cstdio) |

### cstdlib

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
|   Utility   | [cstdlib.hpp](./etl/cstdlib.hpp) | [test_cstdlib.cpp](./tests/test_cstdlib.cpp) |    TODO     | [cstdlib](https://en.cppreference.com/w/cpp/header/cstdlib) |

### cstring

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
|   Strings   | [cstring.hpp](./etl/cstring.hpp) | [test_cstring.cpp](./tests/test_cstring.cpp) |    TODO     | [cstring](https://en.cppreference.com/w/cpp/header/cstring) |

### ctime

| **Library** |          **Source**          |                **Tests**                 | **Example** |                    **cppreference**                     |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :-----------------------------------------------------: |
|   Utility   | [ctime.hpp](./etl/ctime.hpp) | [test_ctime.cpp](./tests/test_ctime.cpp) |    TODO     | [ctime](https://en.cppreference.com/w/cpp/header/ctime) |

### expected

|       **Library**        |             **Source**             |                   **Tests**                    | **Example** |                       **cppreference**                        |
| :----------------------: | :--------------------------------: | :--------------------------------------------: | :---------: | :-----------------------------------------------------------: |
| Utility / Error Handling | [expected.hpp](./etl/expected.hpp) | [test_expected.cpp](./tests/test_expected.cpp) |    TODO     | [expected](https://en.cppreference.com/w/cpp/header/expected) |

### format

| **Library** |           **Source**           |                 **Tests**                  | **Example** |                     **cppreference**                      |
| :---------: | :----------------------------: | :----------------------------------------: | :---------: | :-------------------------------------------------------: |
|   Strings   | [format.hpp](./etl/format.hpp) | [test_format.cpp](./tests/test_format.cpp) |    TODO     | [format](https://en.cppreference.com/w/cpp/header/format) |

### functional

| **Library** |               **Source**               |                     **Tests**                      | **Example** |                         **cppreference**                          |
| :---------: | :------------------------------------: | :------------------------------------------------: | :---------: | :---------------------------------------------------------------: |
|   Utility   | [functional.hpp](./etl/functional.hpp) | [test_functional.cpp](./tests/test_functional.cpp) |    TODO     | [functional](https://en.cppreference.com/w/cpp/header/functional) |

### ios

| **Library**  |        **Source**        |              **Tests**               | **Example** |                  **cppreference**                   |
| :----------: | :----------------------: | :----------------------------------: | :---------: | :-------------------------------------------------: |
| Input/Output | [ios.hpp](./etl/ios.hpp) | [test_ios.cpp](./tests/test_ios.cpp) |    TODO     | [ios](https://en.cppreference.com/w/cpp/header/ios) |

### iterator

| **Library** |             **Source**             |                   **Tests**                    | **Example** |                       **cppreference**                        |
| :---------: | :--------------------------------: | :--------------------------------------------: | :---------: | :-----------------------------------------------------------: |
|  Iterator   | [iterator.hpp](./etl/iterator.hpp) | [test_iterator.cpp](./tests/test_iterator.cpp) |    TODO     | [iterator](https://en.cppreference.com/w/cpp/header/iterator) |

### limits

|       **Library**        |           **Source**           |                 **Tests**                  | **Example** |                     **cppreference**                      |
| :----------------------: | :----------------------------: | :----------------------------------------: | :---------: | :-------------------------------------------------------: |
| Utility / Numeric Limits | [limits.hpp](./etl/limits.hpp) | [test_limits.cpp](./tests/test_limits.cpp) |    TODO     | [limits](https://en.cppreference.com/w/cpp/header/limits) |

### map

| **Library** |        **Source**        |              **Tests**               |          **Example**          |                  **cppreference**                   |
| :---------: | :----------------------: | :----------------------------------: | :---------------------------: | :-------------------------------------------------: |
| Containers  | [map.hpp](./etl/map.hpp) | [test_map.cpp](./tests/test_map.cpp) | [map.cpp](./examples/map.cpp) | [map](https://en.cppreference.com/w/cpp/header/map) |

### memory

|       **Library**        |           **Source**           |                 **Tests**                  |             **Example**             |                     **cppreference**                      |
| :----------------------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :-------------------------------------------------------: |
| Utility / Dynamic Memory | [memory.hpp](./etl/memory.hpp) | [test_memory.cpp](./tests/test_memory.cpp) | [memory.cpp](./examples/memory.cpp) | [memory](https://en.cppreference.com/w/cpp/header/memory) |

### mutex

| **Library** |          **Source**          |                **Tests**                 | **Example** |                    **cppreference**                     |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :-----------------------------------------------------: |
|   Thread    | [mutex.hpp](./etl/mutex.hpp) | [test_mutex.cpp](./tests/test_mutex.cpp) |   TODO a    | [mutex](https://en.cppreference.com/w/cpp/header/mutex) |

### new

|       **Library**        |        **Source**        |              **Tests**               | **Example** |                  **cppreference**                   |
| :----------------------: | :----------------------: | :----------------------------------: | :---------: | :-------------------------------------------------: |
| Utility / Dynamic Memory | [new.hpp](./etl/new.hpp) | [test_new.cpp](./tests/test_new.cpp) |    TODO     | [new](https://en.cppreference.com/w/cpp/header/new) |

### numbers

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
|   Numeric   | [numbers.hpp](./etl/numbers.hpp) | [test_numbers.cpp](./tests/test_numbers.cpp) |    TODO     | [numbers](https://en.cppreference.com/w/cpp/header/numbers) |

### numeric

| **Library** |            **Source**            |                  **Tests**                   |              **Example**              |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :-----------------------------------: | :---------------------------------------------------------: |
|   Numeric   | [numeric.hpp](./etl/numeric.hpp) | [test_numeric.cpp](./tests/test_numeric.cpp) | [numeric.cpp](./examples/numeric.cpp) | [numeric](https://en.cppreference.com/w/cpp/header/numeric) |

### optional

| **Library** |             **Source**             |                   **Tests**                    |               **Example**               |                       **cppreference**                        |
| :---------: | :--------------------------------: | :--------------------------------------------: | :-------------------------------------: | :-----------------------------------------------------------: |
|   Utility   | [optional.hpp](./etl/optional.hpp) | [test_optional.cpp](./tests/test_optional.cpp) | [optional.cpp](./examples/optional.cpp) | [optional](https://en.cppreference.com/w/cpp/header/optional) |

### ratio

| **Library** |          **Source**          |                **Tests**                 | **Example** |                    **cppreference**                     |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :-----------------------------------------------------: |
|   Numeric   | [ratio.hpp](./etl/ratio.hpp) | [test_ratio.cpp](./tests/test_ratio.cpp) |    TODO     | [ratio](https://en.cppreference.com/w/cpp/header/ratio) |

### scope_guard

| **Library** |                **Source**                |                      **Tests**                       | **Example** | cppreference |
| :---------: | :--------------------------------------: | :--------------------------------------------------: | :---------: | :----------: |
|   Utility   | [scope_guard.hpp](./etl/scope_guard.hpp) | [test_scope_guard.cpp](./tests/test_scope_guard.cpp) |    TODO     |              |

### set

| **Library** |        **Source**        |              **Tests**               |          **Example**          |                  **cppreference**                   |
| :---------: | :----------------------: | :----------------------------------: | :---------------------------: | :-------------------------------------------------: |
| Containers  | [set.hpp](./etl/set.hpp) | [test_set.cpp](./tests/test_set.cpp) | [set.cpp](./examples/set.cpp) | [set](https://en.cppreference.com/w/cpp/header/set) |

### span

| **Library** |         **Source**         |               **Tests**                | **Example** |                   **cppreference**                    |
| :---------: | :------------------------: | :------------------------------------: | :---------: | :---------------------------------------------------: |
| Containers  | [span.hpp](./etl/span.hpp) | [test_span.cpp](./tests/test_span.cpp) |    TODO     | [span](https://en.cppreference.com/w/cpp/header/span) |

### stack

| **Library** |          **Source**          |                **Tests**                 | **Example** |                    **cppreference**                     |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :-----------------------------------------------------: |
| Containers  | [stack.hpp](./etl/stack.hpp) | [test_stack.cpp](./tests/test_stack.cpp) |    TODO     | [stack](https://en.cppreference.com/w/cpp/header/stack) |

### string

| **Library** |           **Source**           |                 **Tests**                  |             **Example**             |                     **cppreference**                      |
| :---------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :-------------------------------------------------------: |
|   Strings   | [string.hpp](./etl/string.hpp) | [test_string.cpp](./tests/test_string.cpp) | [string.cpp](./examples/string.cpp) | [string](https://en.cppreference.com/w/cpp/header/string) |

### string_view

| **Library** |                **Source**                |                      **Tests**                       | **Example** |                          **cppreference**                           |
| :---------: | :--------------------------------------: | :--------------------------------------------------: | :---------: | :-----------------------------------------------------------------: |
|   Strings   | [string_view.hpp](./etl/string_view.hpp) | [test_string_view.cpp](./tests/test_string_view.cpp) |    TODO     | [string_view](https://en.cppreference.com/w/cpp/header/string_view) |

### system_error

|       **Library**        |                 **Source**                 |                       **Tests**                        | **Example** |                           **cppreference**                            |
| :----------------------: | :----------------------------------------: | :----------------------------------------------------: | :---------: | :-------------------------------------------------------------------: |
| Utility / Error Handling | [system_error.hpp](./etl/system_error.hpp) | [test_system_error.cpp](./tests/test_system_error.cpp) |    TODO     | [system_error](https://en.cppreference.com/w/cpp/header/system_error) |

### tuple

| **Library** |          **Source**          |                **Tests**                 |            **Example**            |                    **cppreference**                     |
| :---------: | :--------------------------: | :--------------------------------------: | :-------------------------------: | :-----------------------------------------------------: |
|   Utility   | [tuple.hpp](./etl/tuple.hpp) | [test_tuple.cpp](./tests/test_tuple.cpp) | [tuple.cpp](./examples/tuple.cpp) | [tuple](https://en.cppreference.com/w/cpp/header/tuple) |

### type_traits

| **Library** |                **Source**                |                      **Tests**                       |                  **Example**                  |                          **cppreference**                           |
| :---------: | :--------------------------------------: | :--------------------------------------------------: | :-------------------------------------------: | :-----------------------------------------------------------------: |
|   Utility   | [type_traits.hpp](./etl/type_traits.hpp) | [test_type_traits.cpp](./tests/test_type_traits.cpp) | [type_traits.cpp](./examples/type_traits.cpp) | [type_traits](https://en.cppreference.com/w/cpp/header/type_traits) |

### utility

| **Library** |            **Source**            |                  **Tests**                   |              **Example**              |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :-----------------------------------: | :---------------------------------------------------------: |
|   Utility   | [utility.hpp](./etl/utility.hpp) | [test_utility.cpp](./tests/test_utility.cpp) | [utility.cpp](./examples/utility.cpp) | [utility](https://en.cppreference.com/w/cpp/header/utility) |

### variant

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
|   Utility   | [variant.hpp](./etl/variant.hpp) | [test_variant.cpp](./tests/test_variant.cpp) |    TODO     | [variant](https://en.cppreference.com/w/cpp/header/variant) |

### vector

| **Library** |           **Source**           |                 **Tests**                  |             **Example**             |                     **cppreference**                      |
| :---------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :-------------------------------------------------------: |
| Containers  | [vector.hpp](./etl/vector.hpp) | [test_vector.cpp](./tests/test_vector.cpp) | [vector.cpp](./examples/vector.cpp) | [vector](https://en.cppreference.com/w/cpp/header/vector) |

### version

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                      **cppreference**                       |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
|   Utility   | [version.hpp](./etl/version.hpp) | [test_version.cpp](./tests/test_version.cpp) |    TODO     | [version](https://en.cppreference.com/w/cpp/header/version) |

### warning

| **Library** |            **Source**            |                  **Tests**                   | **Example** | cppreference |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :----------: |
|   Utility   | [warning.hpp](./etl/warning.hpp) | [test_warning.cpp](./tests/test_warning.cpp) |    TODO     |              |
