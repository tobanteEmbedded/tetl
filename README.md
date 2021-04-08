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

| **Library** |              **Source**              |                    **Tests**                     |                **Example**                |                                                     **Progress**                                                     |
| :---------: | :----------------------------------: | :----------------------------------------------: | :---------------------------------------: | :------------------------------------------------------------------------------------------------------------------: |
| Algorithms  | [algorithm.hpp](./etl/algorithm.hpp) | [test_algorithm.cpp](./tests/test_algorithm.cpp) | [algorithm.cpp](./examples/algorithm.cpp) | [algorithm](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1451123716) |

#### Changes

- Implementations are optimize for code size.
- All overloads using an execution policy are not implemented.

### array

| **Library** |          **Source**          |                **Tests**                 |            **Example**            |                                                   **Progress**                                                   |
| :---------: | :--------------------------: | :--------------------------------------: | :-------------------------------: | :--------------------------------------------------------------------------------------------------------------: |
| Containers  | [array.hpp](./etl/array.hpp) | [test_array.cpp](./tests/test_array.cpp) | [array.cpp](./examples/array.cpp) | [array](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1320059600) |

#### Changes

- None

### bit

| **Library** |        **Source**        |              **Tests**               | **Example** |                                                  **Progress**                                                  |
| :---------: | :----------------------: | :----------------------------------: | :---------: | :------------------------------------------------------------------------------------------------------------: |
|   Numeric   | [bit.hpp](./etl/bit.hpp) | [test_bit.cpp](./tests/test_bit.cpp) |    TODO     | [bit](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1927645890) |

#### Changes

- None

### bitset

| **Library** |           **Source**           |                 **Tests**                  |             **Example**             |                                                   **Progress**                                                   |
| :---------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :--------------------------------------------------------------------------------------------------------------: |
|   Utility   | [bitset.hpp](./etl/bitset.hpp) | [test_bitset.cpp](./tests/test_bitset.cpp) | [bitset.cpp](./examples/bitset.cpp) | [bitset](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=692946382) |

### cassert

|       **Library**        |            **Source**            |                  **Tests**                   | **Example** |                                                   **Progress**                                                    |
| :----------------------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------------------------------------------------------------: |
| Utility / Error Handling | [cassert.hpp](./etl/cassert.hpp) | [test_cassert.cpp](./tests/test_cassert.cpp) |    TODO     | [cassert](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=460740183) |

#### Changes

- None

### cctype

| **Library** |           **Source**           |                 **Tests**                  | **Example** |                                                   **Progress**                                                   |
| :---------: | :----------------------------: | :----------------------------------------: | :---------: | :--------------------------------------------------------------------------------------------------------------: |
|   Strings   | [cctype.hpp](./etl/cctype.hpp) | [test_cctype.cpp](./tests/test_cctype.cpp) |    TODO     | [cctype](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=522168028) |

#### Changes

- Locale independent

### cfloat

|       **Library**        |           **Source**           |                 **Tests**                  | **Example** |                                                   **Progress**                                                    |
| :----------------------: | :----------------------------: | :----------------------------------------: | :---------: | :---------------------------------------------------------------------------------------------------------------: |
| Utility / Numeric Limits | [cfloat.hpp](./etl/cfloat.hpp) | [test_cfloat.cpp](./tests/test_cfloat.cpp) |    TODO     | [cfloat](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1012838019) |

### charconv

| **Library** |             **Source**             |                   **Tests**                    | **Example** |                                                    **Progress**                                                    |
| :---------: | :--------------------------------: | :--------------------------------------------: | :---------: | :----------------------------------------------------------------------------------------------------------------: |
|   Strings   | [charconv.hpp](./etl/charconv.hpp) | [test_charconv.cpp](./tests/test_charconv.cpp) |    TODO     | [charconv](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=345887816) |

### chrono

| **Library** |           **Source**           |                 **Tests**                  |             **Example**             |                                                   **Progress**                                                    |
| :---------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :---------------------------------------------------------------------------------------------------------------: |
|   Utility   | [chrono.hpp](./etl/chrono.hpp) | [test_chrono.cpp](./tests/test_chrono.cpp) | [chrono.cpp](./examples/chrono.cpp) | [chrono](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1279150724) |

### climits

|       **Library**        |            **Source**            |                  **Tests**                   | **Example** |                                                    **Progress**                                                    |
| :----------------------: | :------------------------------: | :------------------------------------------: | :---------: | :----------------------------------------------------------------------------------------------------------------: |
| Utility / Numeric Limits | [climits.hpp](./etl/climits.hpp) | [test_climits.cpp](./tests/test_climits.cpp) |    TODO     | [climits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1904156895) |

#### Changes

- None

### cmath

| **Library** |          **Source**          |                **Tests**                 | **Example** |                                                  **Progress**                                                   |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :-------------------------------------------------------------------------------------------------------------: |
|   Numeric   | [cmath.hpp](./etl/cmath.hpp) | [test_cmath.cpp](./tests/test_cmath.cpp) |    TODO     | [cmath](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=868070087) |

### concepts

| **Library** |             **Source**             |                   **Tests**                    | **Example** |                                                   **Progress**                                                    |
| :---------: | :--------------------------------: | :--------------------------------------------: | :---------: | :---------------------------------------------------------------------------------------------------------------: |
|  Concepts   | [concepts.hpp](./etl/concepts.hpp) | [test_concepts.cpp](./tests/test_concepts.cpp) |    TODO     | [concepts](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=73781271) |

#### Changes

- None

### cstdarg

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                                                    **Progress**                                                    |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :----------------------------------------------------------------------------------------------------------------: |
|   Utility   | [cstdarg.hpp](./etl/cstdarg.hpp) | [test_cstdarg.cpp](./tests/test_cstdarg.cpp) |    TODO     | [cstdarg](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1280782172) |

#### Changes

- None

### cstddef

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                                                    **Progress**                                                    |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :----------------------------------------------------------------------------------------------------------------: |
|   Utility   | [cstddef.hpp](./etl/cstddef.hpp) | [test_cstddef.cpp](./tests/test_cstddef.cpp) |    TODO     | [cstddef](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1660546405) |

#### Changes

- None

### cstdint

|       **Library**        |            **Source**            |                  **Tests**                   | **Example** | **Progress** |
| :----------------------: | :------------------------------: | :------------------------------------------: | :---------: | :----------: |
| Utility / Numeric Limits | [cstdint.hpp](./etl/cstdint.hpp) | [test_cstdint.cpp](./tests/test_cstdint.cpp) |    TODO     |              |

### cstdio

| **Library**  |           **Source**           |                 **Tests**                  | **Example** |                                                   **Progress**                                                    |
| :----------: | :----------------------------: | :----------------------------------------: | :---------: | :---------------------------------------------------------------------------------------------------------------: |
| Input/Output | [cstdio.hpp](./etl/cstdio.hpp) | [test_cstdio.cpp](./tests/test_cstdio.cpp) |    TODO     | [cstdio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1576270107) |

### cstdlib

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                                                    **Progress**                                                    |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :----------------------------------------------------------------------------------------------------------------: |
|   Utility   | [cstdlib.hpp](./etl/cstdlib.hpp) | [test_cstdlib.cpp](./tests/test_cstdlib.cpp) |    TODO     | [cstdlib](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1705155517) |

### cstring

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                                                    **Progress**                                                    |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :----------------------------------------------------------------------------------------------------------------: |
|   Strings   | [cstring.hpp](./etl/cstring.hpp) | [test_cstring.cpp](./tests/test_cstring.cpp) |    TODO     | [cstring](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1824871501) |

### ctime

| **Library** |          **Source**          |                **Tests**                 | **Example** |                                                   **Progress**                                                   |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :--------------------------------------------------------------------------------------------------------------: |
|   Utility   | [ctime.hpp](./etl/ctime.hpp) | [test_ctime.cpp](./tests/test_ctime.cpp) |    TODO     | [ctime](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1082109762) |

### expected

|       **Library**        |             **Source**             |                   **Tests**                    | **Example** |                                                    **Progress**                                                     |
| :----------------------: | :--------------------------------: | :--------------------------------------------: | :---------: | :-----------------------------------------------------------------------------------------------------------------: |
| Utility / Error Handling | [expected.hpp](./etl/expected.hpp) | [test_expected.cpp](./tests/test_expected.cpp) |    TODO     | [expected](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1624993362) |

### format

| **Library** |           **Source**           |                 **Tests**                  | **Example** |                                                   **Progress**                                                   |
| :---------: | :----------------------------: | :----------------------------------------: | :---------: | :--------------------------------------------------------------------------------------------------------------: |
|   Strings   | [format.hpp](./etl/format.hpp) | [test_format.cpp](./tests/test_format.cpp) |    TODO     | [format](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=159875067) |

### functional

| **Library** |               **Source**               |                     **Tests**                      | **Example** |                                                     **Progress**                                                     |
| :---------: | :------------------------------------: | :------------------------------------------------: | :---------: | :------------------------------------------------------------------------------------------------------------------: |
|   Utility   | [functional.hpp](./etl/functional.hpp) | [test_functional.cpp](./tests/test_functional.cpp) |    TODO     | [functional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=291953395) |

### ios

| **Library**  |        **Source**        |              **Tests**               | **Example** |                                                  **Progress**                                                  |
| :----------: | :----------------------: | :----------------------------------: | :---------: | :------------------------------------------------------------------------------------------------------------: |
| Input/Output | [ios.hpp](./etl/ios.hpp) | [test_ios.cpp](./tests/test_ios.cpp) |    TODO     | [ios](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878) |

### iterator

| **Library** |             **Source**             |                   **Tests**                    | **Example** |                                                    **Progress**                                                     |
| :---------: | :--------------------------------: | :--------------------------------------------: | :---------: | :-----------------------------------------------------------------------------------------------------------------: |
|  Iterator   | [iterator.hpp](./etl/iterator.hpp) | [test_iterator.cpp](./tests/test_iterator.cpp) |    TODO     | [iterator](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878) |

### limits

|       **Library**        |           **Source**           |                 **Tests**                  | **Example** |                                                   **Progress**                                                    |
| :----------------------: | :----------------------------: | :----------------------------------------: | :---------: | :---------------------------------------------------------------------------------------------------------------: |
| Utility / Numeric Limits | [limits.hpp](./etl/limits.hpp) | [test_limits.cpp](./tests/test_limits.cpp) |    TODO     | [limits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878) |

#### Changes

- None

### map

| **Library** |        **Source**        |              **Tests**               |          **Example**          |                                                  **Progress**                                                  |
| :---------: | :----------------------: | :----------------------------------: | :---------------------------: | :------------------------------------------------------------------------------------------------------------: |
| Containers  | [map.hpp](./etl/map.hpp) | [test_map.cpp](./tests/test_map.cpp) | [map.cpp](./examples/map.cpp) | [map](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878) |

### memory

|       **Library**        |           **Source**           |                 **Tests**                  |             **Example**             |                                                   **Progress**                                                    |
| :----------------------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :---------------------------------------------------------------------------------------------------------------: |
| Utility / Dynamic Memory | [memory.hpp](./etl/memory.hpp) | [test_memory.cpp](./tests/test_memory.cpp) | [memory.cpp](./examples/memory.cpp) | [memory](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878) |

### mutex

| **Library** |          **Source**          |                **Tests**                 | **Example** |                                                   **Progress**                                                   |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :--------------------------------------------------------------------------------------------------------------: |
|   Thread    | [mutex.hpp](./etl/mutex.hpp) | [test_mutex.cpp](./tests/test_mutex.cpp) |    TODO     | [mutex](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878) |

### new

|       **Library**        |        **Source**        |              **Tests**               | **Example** |                                                  **Progress**                                                  |
| :----------------------: | :----------------------: | :----------------------------------: | :---------: | :------------------------------------------------------------------------------------------------------------: |
| Utility / Dynamic Memory | [new.hpp](./etl/new.hpp) | [test_new.cpp](./tests/test_new.cpp) |    TODO     | [new](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=2084657878) |

### numbers

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                                                   **Progress**                                                    |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------------------------------------------------------------: |
|   Numeric   | [numbers.hpp](./etl/numbers.hpp) | [test_numbers.cpp](./tests/test_numbers.cpp) |    TODO     | [numbers](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=641824361) |

#### Changes

- None

### numeric

| **Library** |            **Source**            |                  **Tests**                   |              **Example**              |                                                    **Progress**                                                    |
| :---------: | :------------------------------: | :------------------------------------------: | :-----------------------------------: | :----------------------------------------------------------------------------------------------------------------: |
|   Numeric   | [numeric.hpp](./etl/numeric.hpp) | [test_numeric.cpp](./tests/test_numeric.cpp) | [numeric.cpp](./examples/numeric.cpp) | [numeric](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1599843301) |

### optional

| **Library** |             **Source**             |                   **Tests**                    |               **Example**               |                                                    **Progress**                                                     |
| :---------: | :--------------------------------: | :--------------------------------------------: | :-------------------------------------: | :-----------------------------------------------------------------------------------------------------------------: |
|   Utility   | [optional.hpp](./etl/optional.hpp) | [test_optional.cpp](./tests/test_optional.cpp) | [optional.cpp](./examples/optional.cpp) | [optional](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1965816070) |

### ratio

| **Library** |          **Source**          |                **Tests**                 | **Example** |                                                   **Progress**                                                   |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :--------------------------------------------------------------------------------------------------------------: |
|   Numeric   | [ratio.hpp](./etl/ratio.hpp) | [test_ratio.cpp](./tests/test_ratio.cpp) |    TODO     | [ratio](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1383686309) |

#### Changes

- None

### scope_guard

| **Library** |                **Source**                |                      **Tests**                       | **Example** | **Progress** |
| :---------: | :--------------------------------------: | :--------------------------------------------------: | :---------: | :----------: |
|   Utility   | [scope_guard.hpp](./etl/scope_guard.hpp) | [test_scope_guard.cpp](./tests/test_scope_guard.cpp) |    TODO     |              |

### set

| **Library** |        **Source**        |              **Tests**               |          **Example**          |                                                 **Progress**                                                  |
| :---------: | :----------------------: | :----------------------------------: | :---------------------------: | :-----------------------------------------------------------------------------------------------------------: |
| Containers  | [set.hpp](./etl/set.hpp) | [test_set.cpp](./tests/test_set.cpp) | [set.cpp](./examples/set.cpp) | [set](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=930086747) |

### span

| **Library** |         **Source**         |               **Tests**                | **Example** |                                                  **Progress**                                                   |
| :---------: | :------------------------: | :------------------------------------: | :---------: | :-------------------------------------------------------------------------------------------------------------: |
| Containers  | [span.hpp](./etl/span.hpp) | [test_span.cpp](./tests/test_span.cpp) |    TODO     | [span](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1750377555) |

### stack

| **Library** |          **Source**          |                **Tests**                 | **Example** |                                                  **Progress**                                                   |
| :---------: | :--------------------------: | :--------------------------------------: | :---------: | :-------------------------------------------------------------------------------------------------------------: |
| Containers  | [stack.hpp](./etl/stack.hpp) | [test_stack.cpp](./tests/test_stack.cpp) |    TODO     | [stack](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=385809287) |

### string

| **Library** |           **Source**           |                 **Tests**                  |             **Example**             |                                                  **Progress**                                                   |
| :---------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :-------------------------------------------------------------------------------------------------------------: |
|   Strings   | [string.hpp](./etl/string.hpp) | [test_string.cpp](./tests/test_string.cpp) | [string.cpp](./examples/string.cpp) | [string](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=43463000) |

### string_view

| **Library** |                **Source**                |                      **Tests**                       | **Example** |                                                      **Progress**                                                      |
| :---------: | :--------------------------------------: | :--------------------------------------------------: | :---------: | :--------------------------------------------------------------------------------------------------------------------: |
|   Strings   | [string_view.hpp](./etl/string_view.hpp) | [test_string_view.cpp](./tests/test_string_view.cpp) |    TODO     | [string_view](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1803550736) |

#### Changes

- None

### system_error

|       **Library**        |                 **Source**                 |                       **Tests**                        | **Example** |                                                      **Progress**                                                      |
| :----------------------: | :----------------------------------------: | :----------------------------------------------------: | :---------: | :--------------------------------------------------------------------------------------------------------------------: |
| Utility / Error Handling | [system_error.hpp](./etl/system_error.hpp) | [test_system_error.cpp](./tests/test_system_error.cpp) |    TODO     | [system_error](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=635426347) |

### tuple

| **Library** |          **Source**          |                **Tests**                 |            **Example**            |                                                  **Progress**                                                   |
| :---------: | :--------------------------: | :--------------------------------------: | :-------------------------------: | :-------------------------------------------------------------------------------------------------------------: |
|   Utility   | [tuple.hpp](./etl/tuple.hpp) | [test_tuple.cpp](./tests/test_tuple.cpp) | [tuple.cpp](./examples/tuple.cpp) | [tuple](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=857929646) |

### type_traits

| **Library** |                **Source**                |                      **Tests**                       |                  **Example**                  |                                                      **Progress**                                                      |
| :---------: | :--------------------------------------: | :--------------------------------------------------: | :-------------------------------------------: | :--------------------------------------------------------------------------------------------------------------------: |
|   Utility   | [type_traits.hpp](./etl/type_traits.hpp) | [test_type_traits.cpp](./tests/test_type_traits.cpp) | [type_traits.cpp](./examples/type_traits.cpp) | [type_traits](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1691010448) |

#### Changes

- None

### utility

| **Library** |            **Source**            |                  **Tests**                   |              **Example**              |                                                    **Progress**                                                    |
| :---------: | :------------------------------: | :------------------------------------------: | :-----------------------------------: | :----------------------------------------------------------------------------------------------------------------: |
|   Utility   | [utility.hpp](./etl/utility.hpp) | [test_utility.cpp](./tests/test_utility.cpp) | [utility.cpp](./examples/utility.cpp) | [utility](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1484976254) |

#### Changes

- None

### variant

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                                                   **Progress**                                                    |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------------------------------------------------------------: |
|   Utility   | [variant.hpp](./etl/variant.hpp) | [test_variant.cpp](./tests/test_variant.cpp) |    TODO     | [variant](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=503059518) |

### vector

| **Library** |           **Source**           |                 **Tests**                  |             **Example**             |                                                   **Progress**                                                    |
| :---------: | :----------------------------: | :----------------------------------------: | :---------------------------------: | :---------------------------------------------------------------------------------------------------------------: |
| Containers  | [vector.hpp](./etl/vector.hpp) | [test_vector.cpp](./tests/test_vector.cpp) | [vector.cpp](./examples/vector.cpp) | [vector](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit#gid=1613833122) |

### version

| **Library** |            **Source**            |                  **Tests**                   | **Example** |                        **Progress**                         |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :---------------------------------------------------------: |
|   Utility   | [version.hpp](./etl/version.hpp) | [test_version.cpp](./tests/test_version.cpp) |    TODO     | [version](https://en.cppreference.com/w/cpp/header/version) |

### warning

| **Library** |            **Source**            |                  **Tests**                   | **Example** | cppreference |
| :---------: | :------------------------------: | :------------------------------------------: | :---------: | :----------: |
|   Utility   | [warning.hpp](./etl/warning.hpp) | [test_warning.cpp](./tests/test_warning.cpp) |    TODO     |              |
