# TAETL - Embedded Template **Library**

- [Status](#status)
  - [Hosted](#hosted)
  - [Freestanding](#freestanding)
  - [Analysis](#analysis)
- [Design Goals](#design-goals)
- [Quick Start](#quick-start)
- [Project Integration](#project-integration)
  - [Command Line / Makefile](#command-line---makefile)
  - [CMake](#cmake)
  - [PlatformIO](#platformio)
- [Header Overview](#header-overview)
- [Header Detail](#header-detail)

## Status

| **License**                                                                                                                 | **Issues**                                                                                                                     | **Lines of Code**                               |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------- |
| [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) | [![GitHub issues](https://img.shields.io/github/issues/tobanteAudio/taetl.svg)](https://GitHub.com/tobanteAudio/taetl/issues/) | ![](https://sloc.xyz/github/tobanteAudio/taetl) |

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

### Analysis

| **Clang-Tidy**                                                                                                                                                            | **ASAN**                                                                                                                                                | **UBSAN**                                                                                                                                                  | **Coverage**                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [![Clang-Tidy](https://github.com/tobanteAudio/taetl/actions/workflows/clang-tidy.yml/badge.svg)](https://github.com/tobanteAudio/taetl/actions/workflows/clang-tidy.yml) | [![ASAN](https://github.com/tobanteAudio/taetl/actions/workflows/asan.yml/badge.svg)](https://github.com/tobanteAudio/taetl/actions/workflows/asan.yml) | [![UBSAN](https://github.com/tobanteAudio/taetl/actions/workflows/ubsan.yml/badge.svg)](https://github.com/tobanteAudio/taetl/actions/workflows/ubsan.yml) | [![codecov](https://codecov.io/gh/tobanteAudio/taetl/branch/main/graph/badge.svg)](https://codecov.io/gh/tobanteAudio/taetl) |

## Design Goals

- 100% portable (no STL headers required, minimum of C headers)
- Header only
- C++17 and beyond (freestanding or hosted)
- Similar API to the STL
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

- [Implementation Progress (Spreadsheet)](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing)
- [API Reference](https://tobanteaudio.github.io/taetl/index.html)

For examples look at the [examples](./examples) subdirectory or the test files in [tests](./tests).

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

|          **Header**           |       **Library**        |     **Status**     |                                               **Progress (Spreadsheet)**                                               |
| :---------------------------: | :----------------------: | :----------------: | :--------------------------------------------------------------------------------------------------------------------: |
|    [algorithm](#algorithm)    |        Algorithms        | :heavy_check_mark: |  [algorithm](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1451123716)  |
|              any              |         Utility          |        :x:         |                                                                                                                        |
|        [array](#array)        |        Containers        | :heavy_check_mark: |    [array](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1320059600)    |
|            atomic             |          Atomic          |        :x:         |                                                                                                                        |
|            barrier            |          Thread          |        :x:         |                                                                                                                        |
|          [bit](#bit)          |         Numeric          | :heavy_check_mark: |     [bit](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1927645890)     |
|       [bitset](#bitset)       |         Utility          | :heavy_check_mark: |    [bitset](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=692946382)    |
|      [cassert](#cassert)      | Utility / Error Handling | :heavy_check_mark: |   [cassert](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=460740183)    |
|       [cctype](#cctype)       |         Strings          | :heavy_check_mark: |    [cctype](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=522168028)    |
|            cerrno             | Utility / Error Handling |        :x:         |                                                                                                                        |
|             cfenv             |         Numeric          |        :x:         |                                                          TODO                                                          |
|       [cfloat](#cfloat)       | Utility / Numeric Limits | :heavy_check_mark: |   [cfloat](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1012838019)    |
|     [charconv](#charconv)     |         Strings          | :heavy_check_mark: |   [charconv](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=345887816)   |
|       [chrono](#chrono)       |         Utility          | :heavy_check_mark: |   [chrono](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1279150724)    |
|           cinttypes           | Utility / Numeric Limits |        :x:         |                                                          TODO                                                          |
|      [climits](#climits)      | Utility / Numeric Limits | :heavy_check_mark: |   [climits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1904156895)   |
|            clocale            |       Localization       |        :x:         |                                                                                                                        |
|        [cmath](#cmath)        |         Numeric          | :heavy_check_mark: |    [cmath](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=868070087)     |
|            compare            |         Utility          |        :x:         |                                                          TODO                                                          |
|            complex            |         Numeric          |        :x:         |                                                          TODO                                                          |
|     [concepts](#concepts)     |         Concepts         | :heavy_check_mark: |   [concepts](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=73781271)    |
|      condition_variable       |          Thread          |        :x:         |                                                                                                                        |
|           coroutine           |        Coroutines        |        :x:         |                                                                                                                        |
|            csetjmp            |         Utility          |        :x:         |                                                                                                                        |
|            csignal            |         Utility          |        :x:         |                                                                                                                        |
|      [cstdarg](#cstdarg)      |         Utility          | :heavy_check_mark: |   [cstdarg](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1280782172)   |
|      [cstddef](#cstddef)      |         Utility          | :heavy_check_mark: |   [cstddef](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1660546405)   |
|      [cstdint](#cstdint)      | Utility / Numeric Limits | :heavy_check_mark: |                                                                                                                        |
|       [cstdio](#cstdio)       |       Input/Output       | :heavy_check_mark: |   [cstdio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1576270107)    |
|      [cstdlib](#cstdlib)      |         Utility          | :heavy_check_mark: |   [cstdlib](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1705155517)   |
|      [cstring](#cstring)      |         Strings          | :heavy_check_mark: |   [cstring](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1824871501)   |
|        [ctime](#ctime)        |         Utility          | :heavy_check_mark: |    [ctime](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1082109762)    |
|            cuchar             |         Strings          |        :x:         |                                                                                                                        |
|            cwchar             |         Strings          |        :x:         |                                                                                                                        |
|            cwctype            |         Strings          |        :x:         |                                                                                                                        |
|             deque             |        Containers        |        :x:         |                                                          TODO                                                          |
|           exception           | Utility / Error Handling |        :x:         |                                                                                                                        |
|           execution           |        Algorithms        |        :x:         |                                                                                                                        |
|     [expected](#expected)     | Utility / Error Handling | :heavy_check_mark: |  [expected](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1624993362)   |
|          filesystem           |        Filesystem        |        :x:         |                                                                                                                        |
|       [format](#format)       |         Strings          | :heavy_check_mark: |    [format](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=159875067)    |
|         forward_list          |        Containers        |        :x:         |                                                                                                                        |
|   [functional](#functional)   |         Utility          | :heavy_check_mark: |  [functional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=291953395)  |
|            future             |          Thread          |        :x:         |                                                                                                                        |
|            fstream            |       Input/Output       |        :x:         |                                                                                                                        |
|           ifstream            |       Input/Output       |        :x:         |                                                                                                                        |
|       initializer_list        |         Utility          |        :x:         |                                                                                                                        |
|            iomanip            |       Input/Output       |        :x:         |                                                                                                                        |
|          [ios](#ios)          |       Input/Output       | :heavy_check_mark: |     [ios](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)     |
|            iosfwd             |       Input/Output       |        :x:         |                                                                                                                        |
|           iostream            |       Input/Output       |        :x:         |                                                                                                                        |
|     [iterator](#iterator)     |         Iterator         | :heavy_check_mark: |  [iterator](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)   |
|            istream            |       Input/Output       |        :x:         |                                                                                                                        |
|             latch             |          Thread          |        :x:         |                                                                                                                        |
|       [limits](#limits)       | Utility / Numeric Limits | :heavy_check_mark: |   [limits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)    |
|             list              |        Containers        |        :x:         |                                                                                                                        |
|            locale             |       Localization       |        :x:         |                                                                                                                        |
|          [map](#map)          |        Containers        | :heavy_check_mark: |     [map](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)     |
|       [memory](#memory)       | Utility / Dynamic Memory | :heavy_check_mark: |   [memory](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)    |
|        memory_resource        | Utility / Dynamic Memory |        :x:         |                                                                                                                        |
|        [mutex](#mutex)        |      Thread Support      | :heavy_check_mark: |    [mutex](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)    |
|          [new](#new)          | Utility / Dynamic Memory | :heavy_check_mark: |     [new](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)     |
|      [numbers](#numbers)      |         Numeric          | :heavy_check_mark: |   [numbers](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=641824361)    |
|      [numeric](#numeric)      |         Numeric          | :heavy_check_mark: |   [numeric](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1599843301)   |
|     [optional](#optional)     |         Utility          | :heavy_check_mark: |  [optional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1965816070)   |
|            ostream            |       Input/Output       |        :x:         |                                                                                                                        |
|             queue             |        Containers        |        :x:         |                                                          TODO                                                          |
|            random             |         Numeric          |        :x:         |                                                                                                                        |
|            ranges             |          Ranges          |        :x:         |                                                          TODO                                                          |
|             regex             |   Regular Expressions    |        :x:         |                                                                                                                        |
|        [ratio](#ratio)        |         Numeric          | :heavy_check_mark: |    [ratio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1383686309)    |
|       scoped_allocator        | Utility / Dynamic Memory |        :x:         |                                                                                                                        |
|  [scope_guard](#scope_guard)  |         Utility          | :heavy_check_mark: |                                                                                                                        |
|           semaphore           |          Thread          |        :x:         |                                                                                                                        |
|        source_location        |         Utility          |        :x:         |                                                                                                                        |
|          [set](#set)          |        Containers        | :heavy_check_mark: |     [set](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=930086747)      |
|         shared_mutex          |          Thread          |        :x:         |                                                                                                                        |
|         [span](#span)         |        Containers        | :heavy_check_mark: |    [span](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1750377555)     |
|        [stack](#stack)        |        Containers        | :heavy_check_mark: |    [stack](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=385809287)     |
|          stack_trace          |         Utility          |        :x:         |                                                                                                                        |
|           stdexcept           | Utility / Error Handling |        :x:         |                                                                                                                        |
|           streambuf           |       Input/Output       |        :x:         |                                                                                                                        |
|       [string](#string)       |         Strings          | :heavy_check_mark: |    [string](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=43463000)     |
|  [string_view](#string_view)  |         Strings          | :heavy_check_mark: | [string_view](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1803550736) |
|          stop_token           |          Thread          |        :x:         |                                                                                                                        |
|            sstream            |       Input/Output       |        :x:         |                                                                                                                        |
| [system_error](#system_error) | Utility / Error Handling | :heavy_check_mark: | [system_error](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=635426347) |
|          sync_stream          |       Input/Output       |        :x:         |                                                                                                                        |
|            thread             |          Thread          |        :x:         |                                                                                                                        |
|        [tuple](#tuple)        |         Utility          | :heavy_check_mark: |    [tuple](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=857929646)     |
|          type_index           |         Utility          |        :x:         |                                                                                                                        |
|           type_info           |         Utility          |        :x:         |                                                                                                                        |
|  [type_traits](#type_traits)  |         Utility          | :heavy_check_mark: | [type_traits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1691010448) |
|         unordered_map         |        Containers        |        :x:         |                                                          TODO                                                          |
|         unordered_set         |        Containers        |        :x:         |                                                          TODO                                                          |
|      [utility](#utility)      |         Utility          | :heavy_check_mark: |   [utility](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1484976254)   |
|           valarray            |         Numeric          |        :x:         |                                                                                                                        |
|      [variant](#variant)      |         Utility          | :heavy_check_mark: |   [variant](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=503059518)    |
|       [vector](#vector)       |        Containers        | :heavy_check_mark: |   [vector](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1613833122)    |
|      [version](#version)      |         Utility          | :heavy_check_mark: |                                                                                                                        |
|      [warning](#warning)      |         Utility          | :heavy_check_mark: |                                                     Not standard.                                                      |

## Header Detail

### algorithm

- **Library:** Algorithms
- **Include:** [`etl/algorithm.hpp`](./etl/algorithm.hpp)
- **Tests:** [test_algorithm.cpp](./tests/test_algorithm.cpp)
- **Example:** [algorithm.cpp](./examples/algorithm.cpp)
- **Progress:** [algorithm](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1451123716)
- **Changes:**
  - Implementations are optimize for code size.
  - All overloads using an execution policy are not implemented.

### array

- **Library:** Containers
- **Include:** [`etl/array.hpp`](./etl/array.hpp)
- **Tests:** [test_array.cpp](./tests/test_array.cpp)
- **Example:** [array.cpp](./examples/array.cpp)
- **Progress:** [array](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1320059600)
- **Changes:**
  - None

### bit

- **Library:** Numeric
- **Include:** [`etl/bit.hpp`](./etl/bit.hpp)
- **Tests:** [test_bit.cpp](./tests/test_bit.cpp)
- **Example:** [bit.cpp](./examples/bit.cpp)
- **Progress:** [bit](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1927645890)
- **Changes:**
  - None

### bitset

- **Library:** Utility
- **Include:** [`etl/bitset.hpp`](./etl/bitset.hpp)
- **Tests:** [test_bitset.cpp](./tests/test_bitset.cpp)
- **Example:** [bitset.cpp](./examples/bitset.cpp)
- **Progress:** [bitset](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=692946382)
- **Changes:**
  - TODO

### cassert

- **Library:** Utility / Error Handling
- **Include:** [`etl/cassert.hpp`](./etl/cassert.hpp)
- **Tests:** [test_cassert.cpp](./tests/test_cassert.cpp)
- **Example:** [cassert.cpp](./examples/cassert.cpp)
- **Progress:** [cassert](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=460740183)
- **Changes:**
  - None

### cctype

- **Library:** Strings
- **Include:** [`etl/cctype.hpp`](./etl/cctype.hpp)
- **Tests:** [test_cctype.cpp](./tests/test_cctype.cpp)
- **Example:** TODO
- **Progress:** [cctype](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=522168028)
- **Changes:**
  - Locale independent

### cfloat

- **Library:** Utility / Numeric Limits
- **Include:** [`etl/cfloat.hpp`](./etl/cfloat.hpp)
- **Tests:** [test_cfloat.cpp](./tests/test_cfloat.cpp)
- **Example:** TODO
- **Progress:** [cfloat](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1012838019)
- **Changes:**
  - None

### charconv

- **Library:** Strings
- **Include:** [`etl/charconv.hpp`](./etl/charconv.hpp)
- **Tests:** [test_charconv.cpp](./tests/test_charconv.cpp)
- **Example:** TODO
- **Progress:** [charconv](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=345887816)
- **Changes:**
  - None

### chrono

- **Library:** Utility
- **Include:** [`etl/chrono.hpp`](./etl/chrono.hpp)
- **Tests:** [test_chrono.cpp](./tests/test_chrono.cpp)
- **Example:** [chrono.cpp](./examples/chrono.cpp)
- **Progress:** [chrono](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1279150724)a
- **Changes:**
  - None

### climits

- **Library:** Utility / Numeric Limits
- **Include:** [`etl/climits.hpp`](./etl/climits.hpp)
- **Tests:** [test_climits.cpp](./tests/test_climits.cpp)
- **Example:** TODO
- **Progress:** [climits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1904156895)
- **Changes:**
  - None

### cmath

- **Library:** Numeric
- **Include:** [`etl/cmath.hpp`](./etl/cmath.hpp)
- **Tests:** [test_cmath.cpp](./tests/test_cmath.cpp)
- **Example:** TODO
- **Progress:** [cmath](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=868070087)
- **Changes:**
  - None

### concepts

- **Library:** Concepts
- **Include:** [`etl/concepts.hpp`](./etl/concepts.hpp)
- **Tests:** [test_concepts.cpp](./tests/test_concepts.cpp)
- **Example:** TODO
- **Progress:** [concepts](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=73781271)
- **Changes:**
  - None

### cstdarg

- **Library:** Utility
- **Include:** [`etl/cstdarg.hpp`](./etl/cstdarg.hpp)
- **Tests:** [test_cstdarg.cpp](./tests/test_cstdarg.cpp)
- **Example:** TODO
- **Progress:** [cstdarg](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1280782172)
- **Changes:**
  - None

### cstddef

- **Library:** Utility
- **Include:** [`etl/cstddef.hpp`](./etl/cstddef.hpp)
- **Tests:** [test_cstddef.cpp](./tests/test_cstddef.cpp)
- **Example:** TODO
- **Progress:** [cstddef](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1660546405)
- **Changes:**
  - None

### cstdint

- **Library:** Utility / Numeric Limits
- **Include:** [`etl/cstdint.hpp`](./etl/cstdint.hpp)
- **Tests:** [test_cstdint.cpp](./tests/test_cstdint.cpp)
- **Example:** TODO
- **Progress:** [cstdint](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2005735528)
- **Changes:**
  - None

### cstdio

- **Library:** Input/Output
- **Include:** [`etl/cstdio.hpp`](./etl/cstdio.hpp)
- **Tests:** [test_cstdio.cpp](./tests/test_cstdio.cpp)
- **Example:** TODO
- **Progress:** [cstdio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1576270107)
- **Changes:**
  - TODO

### cstdlib

- **Library:** Utility
- **Include:** [`etl/cstdlib.hpp`](./etl/cstdlib.hpp)
- **Tests:** [test_cstdlib.cpp](./tests/test_cstdlib.cpp)
- **Example:** TODO
- **Progress:** [cstdlib](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1705155517)
- **Changes:**
  - None

### cstring

- **Library:** Strings
- **Include:** [`etl/cstring.hpp`](./etl/cstring.hpp)
- **Tests:** [test_cstring.cpp](./tests/test_cstring.cpp)
- **Example:** TODO
- **Progress:** [cstring](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1824871501)
- **Changes:**
  - TODO

### ctime

- **Library:** Utility
- **Include:** [`etl/ctime.hpp`](./etl/ctime.hpp)
- **Tests:** [test_ctime.cpp](./tests/test_ctime.cpp)
- **Example:** TODO
- **Progress:** [ctime](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1082109762)
- **Changes:**
  - TODO

### expected

- **Library:** Utility / Error Handling
- **Include:** [`etl/expected.hpp`](./etl/expected.hpp)
- **Tests:** [test_expected.cpp](./tests/test_expected.cpp)
- **Example:** TODO
- **Progress:** [expected](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1624993362)
- **Changes:**
  - TODO

### format

- **Library:** Strings
- **Include:** [`etl/format.hpp`](./etl/format.hpp)
- **Tests:** [test_format.cpp](./tests/test_format.cpp)
- **Example:** TODO
- **Progress:** [format](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=159875067)
- **Changes:**
  - TODO

### functional

- **Library:** Utility
- **Include:** [`etl/functional.hpp`](./etl/functional.hpp)
- **Tests:** [test_functional.cpp](./tests/test_functional.cpp)
- **Example:** TODO
- **Progress:** [functional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=291953395)
- **Changes:**
  - TODO

### ios

- **Library:** Input/Output
- **Include:** [`etl/ios.hpp`](./etl/ios.hpp)
- **Tests:** [test_ios.cpp](./tests/test_ios.cpp)
- **Example:** TODO
- **Progress:** [ios](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)
- **Changes:**
  - TODO

### iterator

- **Library:** Iterator
- **Include:** [`etl/iterator.hpp`](./etl/iterator.hpp)
- **Tests:** [test_iterator.cpp](./tests/test_iterator.cpp)
- **Example:** TODO
- **Progress:** [iterator](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)
- **Changes:**
  - TODO

### limits

- **Library:** Utility / Numeric Limits
- **Include:** [`etl/limits.hpp`](./etl/limits.hpp)
- **Tests:** [test_limits.cpp](./tests/test_limits.cpp)
- **Example:** TODO
- **Progress:** [limits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)
- **Changes:**
  - TODO

### map

- **Library:** Containers
- **Include:** [`etl/map.hpp`](./etl/map.hpp)
- **Tests:** [test_map.cpp](./tests/test_map.cpp)
- **Example:** [map.cpp](./examples/map.cpp)
- **Progress:** [map](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)
- **Changes:**
  - TODO

### memory

- **Library:** Utility / Dynamic Memory
- **Include:** [`etl/memory.hpp`](./etl/memory.hpp)
- **Tests:** [test_memory.cpp](./tests/test_memory.cpp)
- **Example:** [memory.cpp](./examples/memory.cpp)
- **Progress:** [memory](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)
- **Changes:**
  - TODO

### mutex

- **Library:** Thread
- **Include:** [`etl/mutex.hpp`](./etl/mutex.hpp)
- **Tests:** [test_mutex.cpp](./tests/test_mutex.cpp)
- **Example:** [mutex.cpp](./examples/mutex.cpp)
- **Progress:** [mutex](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)
- **Changes:**
  - TODO

### new

- **Library:** Utility / Dynamic Memory
- **Include:** [`etl/new.hpp`](./etl/new.hpp)
- **Tests:** [test_new.cpp](./tests/test_new.cpp)
- **Example:** TODO
- **Progress:** [new](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878)
- **Changes:**
  - TODO

### numbers

- **Library:** Numeric
- **Include:** [`etl/numbers.hpp`](./etl/numbers.hpp)
- **Tests:** [test_numbers.cpp](./tests/test_numbers.cpp)
- **Example:** TODO
- **Progress:** [numbers](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=641824361)
- **Changes:**
  - None

### numeric

- **Library:** Numeric
- **Include:** [`etl/numeric.hpp`](./etl/numeric.hpp)
- **Tests:** [test_numeric.cpp](./tests/test_numeric.cpp)
- **Example:** [numeric.cpp](./examples/numeric.cpp)
- **Progress:** [numeric](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1599843301)
- **Changes:**
  - TODO

### optional

- **Library:** Utility
- **Include:** [`etl/optional.hpp`](./etl/optional.hpp)
- **Tests:** [test_optional.cpp](./tests/test_optional.cpp)
- **Example:** [optional.cpp](./examples/optional.cpp)
- **Progress:** [optional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1965816070)
- **Changes:**
  - TODO

### ratio

- **Library:** Numeric
- **Include:** [`etl/ratio.hpp`](./etl/ratio.hpp)
- **Tests:** [test_ratio.cpp](./tests/test_ratio.cpp)
- **Example:** [ratio.cpp](./examples/ratio.cpp)
- **Progress:** [ratio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1383686309)
- **Changes:**
  - TODO

### scope_guard

- **Library:** Utility
- **Include:** [`etl/scope_guard.hpp`](./etl/scope_guard.hpp)
- **Tests:** [test_scope_guard.cpp](./tests/test_scope_guard.cpp)
- **Example:** TODO
- **Progress:** TODO
- **Changes:**
  - TODO

### set

- **Library:** Containers
- **Include:** [`etl/set.hpp`](./etl/set.hpp)
- **Tests:** [test_set.cpp](./tests/test_set.cpp)
- **Example:** [set.cpp](./examples/set.cpp)
- **Progress:** [set](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=930086747)
- **Changes:**
  - TODO

### span

- **Library:** Containers
- **Include:** [`etl/span.hpp`](./etl/span.hpp)
- **Tests:** [test_span.cpp](./tests/test_span.cpp)
- **Example:** TODO
- **Progress:** [span](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1750377555)
- **Changes:**
  - TODO

### stack

- **Library:** Containers
- **Include:** [`etl/stack.hpp`](./etl/stack.hpp)
- **Tests:** [test_stack.cpp](./tests/test_stack.cpp)
- **Example:** TODO
- **Progress:** [stack](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=385809287)
- **Changes:**
  - TODO

### string

- **Library:** Strings
- **Include:** [`etl/string.hpp`](./etl/string.hpp)
- **Tests:** [test_string.cpp](./tests/test_string.cpp)
- **Example:** [string.cpp](./examples/string.cpp)
- **Progress:** [string](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=43463000)
- **Changes:**
  - TODO

### string_view

- **Library:** Strings
- **Include:** [`etl/string_view.hpp`](./etl/string_view.hpp)
- **Tests:** [test_string_view.cpp](./tests/test_string_view.cpp)
- **Example:** [string_view.cpp](./examples/string_view.cpp)
- **Progress:** [string_view](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1803550736)
- **Changes:**
  - None

### system_error

- **Library:** Utility / Error Handling
- **Include:** [`etl/system_error.hpp`](./etl/system_error.hpp)
- **Tests:** [test_system_error.cpp](./tests/test_system_error.cpp)
- **Example:** TODO
- **Progress:** [system_error](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=635426347)
- **Changes:**
  - TODO

### tuple

- **Library:** Utility
- **Include:** [`etl/tuple.hpp`](./etl/tuple.hpp)
- **Tests:** [test_tuple.cpp](./tests/test_tuple.cpp)
- **Example:** [tuple.cpp](./examples/tuple.cpp)
- **Progress:** [tuple](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=857929646)
- **Changes:**
  - TODO

### type_traits

- **Library:** Utility
- **Include:** [`etl/type_traits.hpp`](./etl/type_traits.hpp)
- **Tests:** [test_type_traits.cpp](./tests/test_type_traits.cpp)
- **Example:** [type_traits.cpp](./examples/type_traits.cpp)
- **Progress:** [type_traits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1691010448)
- **Changes:**
  - TODO

### utility

- **Library:** Utility
- **Include:** [`etl/utility.hpp`](./etl/utility.hpp)
- **Tests:** [test_utility.cpp](./tests/test_utility.cpp)
- **Example:** [utility.cpp](./examples/utility.cpp)
- **Progress:** [utility](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1484976254)
- **Changes:**
  - TODO

### variant

- **Library:** Utility
- **Include:** [`etl/variant.hpp`](./etl/variant.hpp)
- **Tests:** [test_variant.cpp](./tests/test_variant.cpp)
- **Example:** TODO
- **Progress:** [variant](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=503059518)
- **Changes:**
  - TODO

### vector

- **Library:** Containers
- **Include:** [`etl/vector.hpp`](./etl/vector.hpp)
- **Tests:** [test_vector.cpp](./tests/test_vector.cpp)
- **Example:** [vector.cpp](./examples/vector.cpp)
- **Progress:** [vector](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1613833122)
- **Changes:**
  - TODO

### version

- **Library:** Utility
- **Include:** [`etl/version.hpp`](./etl/version.hpp)
- **Tests:** [test_version.cpp](./tests/test_version.cpp)
- **Example:** TODO
- **Progress:** TODO
- **Changes:**
  - TODO

### warning

- **Library:** Utility
- **Include:** [`etl/warning.hpp`](./etl/warning.hpp)
- **Tests:** [test_warning.cpp](./tests/test_warning.cpp)
- **Example:** TODO
- **Progress:** TODO
- **Changes:**
  - TODO
