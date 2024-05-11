# Embedded Template Library

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

## Quick Start

```cpp
#include <etl/algorithm.hpp>
#include <etl/array.hpp>

auto main() -> int {
  auto const numbers = etl::array{1, 2, 3, 4, 5};
  auto const greater_two = [] (auto const v) { return v > 2; };
  return etl::count_if(numbers.begin(), numbers.end(), greater_two);
}
```

```sh
g++ -Wall -Wextra -Wpedantic -std=c++20 -I path/to/tetl/include main.cpp
```

For examples look at the [examples](./examples) subdirectory or the test files in [tests](./tests). The [API reference](https://tobanteembedded.github.io/tetl-docs/) is currently work in progress.

## Status

| **License**                                                                                                                                 | **Lines of Code**                                       | **Progress**                                                                                                                                       | **Documentation**                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [![License](https://img.shields.io/badge/License-Boost%201.0-lightblue.svg)](https://github.com/tobanteEmbedded/tetl/blob/main/LICENSE.txt) | ![LOC](https://tokei.rs/b1/github/tobanteEmbedded/tetl) | [Spreadsheet](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing) / [Papers](./docs/progress.md) | [API Reference](https://tobanteembedded.github.io/tetl-docs/) |

### Hosted

| **Platform** |                                                                                  **Status**                                                                                   |              **Notes**              |
| :----------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :---------------------------------: |
|  **Linux**   |        [![Linux](https://github.com/tobanteEmbedded/tetl/actions/workflows/linux.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/linux.yml)         |    GCC 11/12/13 & Clang 16/17/18    |
|  **macOS**   |        [![macOS](https://github.com/tobanteEmbedded/tetl/actions/workflows/macos.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/macos.yml)         |          Xcode x64 & ARM64          |
| **Windows**  |     [![Windows](https://github.com/tobanteEmbedded/tetl/actions/workflows/windows.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/windows.yml)      | Visual Studio 2022, ClangCL & Clang |
| **JS/WASM**  | [![Emscripten](https://github.com/tobanteEmbedded/tetl/actions/workflows/emscripten.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/emscripten.yml) |          Emscripten Latest          |

### Freestanding

| **Platform** |                                                                                         **Status**                                                                                          | **Notes** |
| :----------: | :-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :-------: |
|   **ARM**    |     [![ARM](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-arm.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-arm.yml)      |  GCC 13   |
|   **AVR**    |     [![AVR](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-avr.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-avr.yml)      |  GCC 14   |
|  **MSP430**  | [![MSP430](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-msp430.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/freestanding-msp430.yml) |  GCC 13   |

### Analysis

|    **Type**    |                                                                                  **Status**                                                                                   | **Notes** |
| :------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :-------: |
|  **Coverage**  |               [![codecov](https://codecov.io/gh/tobanteEmbedded/tetl/branch/main/graph/badge.svg?token=f1QAWTtpIo)](https://codecov.io/gh/tobanteEmbedded/tetl)               |  GCC 11   |
| **Sanitizers** | [![ASAN/UBSAN](https://github.com/tobanteEmbedded/tetl/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/sanitizers.yml) | Clang 18  |
| **Clang-Tidy** | [![Clang-Tidy](https://github.com/tobanteEmbedded/tetl/actions/workflows/clang-tidy.yml/badge.svg)](https://github.com/tobanteEmbedded/tetl/actions/workflows/clang-tidy.yml) | Clang 18  |

> [!NOTE]
> All test are compiled in debug and release mode with at least `-Wall -Wextra -Wpedantic -Werror` or `/W3 /WX`. The full list of warning flags can be found in the CMake configuration: [cmake/compiler_warnings.cmake](./cmake/compiler_warnings.cmake). Hosted platforms run all tests & examples, while freestanding builds only compile (ARM & AVR) and link (AVR) the example files.

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

For more details about the global assertion handler `etl::assert_handler` & the assertion macro `TETL_ASSERT` see the [examples/cassert.cpp](./examples/cassert.cpp) file.

## Project Integration

The following steps explain how to add `etl` to your project. Embedded or desktop.

```sh
cd path/to/your/project
mkdir 3rd_party
git submodule add https://github.com/tobanteEmbedded/tetl.git 3rd_party/tetl
```

### Command Line

```make
CXXFLAGS += -std=c++20 -I3rd_party/tetl/include
```

### CMake

Add `tetl` as a git submodule, then add these lines to your `CMakeLists.txt`:

```cmake
# tetl::etl is an interface target.
# The target only sets the include path. No static library is created.

add_subdirectory(3rd_party/tetl/include EXCLUDE_FROM_ALL)
target_link_libraries(${YOUR_TARGET} tetl::etl)
```

### PlatformIO

Add `tetl` as a git submodule, then add these lines to your `platformio.ini`:

```ini
; Most Arduino code does not compile unless you have GNU extensions enabled.
[env:yourenv]
build_unflags = -std=gnu++11
build_flags = -std=gnu++20 -Wno-register -I 3rd_party/tetl/include
```
