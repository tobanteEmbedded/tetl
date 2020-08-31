# TAETL

The tobanteAudio embedded template library is intended for micro controller where the `STL` is not available. Designed to have a similar API. This library supports `AVR/Arduino` micro controllers.

```sh
git clone https://github.com/tobanteAudio/taetl.git
```

## Status

|                                                           LICENSE                                                           |                                                      Linux / macOS                                                      |                                                                  Windows                                                                  |                                                                  AVR                                                                  |                                    Issues                                     |                                                         Code Coverage                                                          |                                                                                                                          Codacy                                                                                                                           |
| :-------------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------: | :----------------------------------------------------------------------------------------------------------------------------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) | [![Build Status](https://travis-ci.org/tobanteAudio/taetl.svg?branch=master)](https://travis-ci.org/tobanteAudio/taetl) | [![AppVeyor Build status](https://img.shields.io/appveyor/ci/tobanteAudio/taetl.svg)](https://ci.appveyor.com/project/tobanteAudio/taetl) | [![Cirrus CI Build Status](https://api.cirrus-ci.com/github/tobanteAudio/taetl.svg)](https://cirrus-ci.com/github/tobanteAudio/taetl) | ![GitHub issues](https://img.shields.io/github/issues/tobanteAudio/taetl.svg) | [![codecov](https://codecov.io/gh/tobanteAudio/taetl/branch/master/graph/badge.svg)](https://codecov.io/gh/tobanteAudio/taetl) | [![Codacy Badge](https://api.codacy.com/project/badge/Grade/80518b423ad649649e782a3773d4e17b)](https://app.codacy.com/app/tobanteAudio/taetl?utm_source=github.com&utm_medium=referral&utm_content=tobanteAudio/taetl&utm_campaign=Badge_Grade_Dashboard) |

## Design Goals

- 100% portable
  - C++ freestanding
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

## Documentation

If you build this repo with `cmake`, html documentation will be created automatically.

```sh
firefox build/doc-build/html/index.html       # Open in Firefox
```

You can build the documentation with `doxygen`:

```sh
cd $PROJECTROOT
doxygen docs/Doxyfile.in
firefox docs/doc-build/html/index.html       # Open in Firefox
```

## Project Integration

The following steps explain how to add `etl` to your project. Embedded or desktop.

### Required Headers

The following headers are required for building the library:

```cpp
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <float.h>
#include <math.h>
```

### CMake

Add `taetl` as a git submodule, then add these lines to your `CMakeLists.txt`:

```sh
cd $YOUR_CMAKE_PROJECT
mkdir 3rd_party
git submodule add https://github.com/tobanteAudio/taetl.git 3rd_party/taetl
```

```cmake
add_subdirectory(3rd_party/taetl)
target_link_libraries(${YOUR_TARGET} tobanteAudio::etl)
```

### PlatformIO

Add `taetl` as a git submodule, then add these lines to your `platformio.ini`:

```sh
cd $YOUR_PLATFORMIO_PROJECT
mkdir 3rd_party
git submodule add https://github.com/tobanteAudio/taetl.git 3rd_party/taetl
```

```ini
[env:yourenv]
; ...
build_unflags = -std=gnu++11
build_flags = -std=gnu++17 -Wno-register -I 3rd_party/taetl
```

## Examples

Examples can be found in the `examples` directory.

### Build on Desktop

```sh
cd $PROJECT_ROOT
mkdir build && cd build
cmake ..
cmake --build  .
```

## Usage

For detailed examples look at the `examples` subdirectory or the test files in `tests`. Building the [documentation](#documentation) with `doxygen` will give details about the complete API.

## Roadmap

- Algorithm
  - [all_of](https://en.cppreference.com/w/cpp/algorithm/all_any_none_of)
  - [count](https://en.cppreference.com/w/cpp/algorithm/count)
  - [equal](https://en.cppreference.com/w/cpp/algorithm/equal)
  - [mismatch](https://en.cppreference.com/w/cpp/algorithm/mismatch)
  - [find_end](https://en.cppreference.com/w/cpp/algorithm/find_end)
  - [find_first_of](https://en.cppreference.com/w/cpp/algorithm/find_first_of)
  - [adjacent_find](https://en.cppreference.com/w/cpp/algorithm/adjacent_find)
  - [search](https://en.cppreference.com/w/cpp/algorithm/search)
  - [search_n](https://en.cppreference.com/w/cpp/algorithm/search_n)
- Array
  - Deduction guide
  - Aggregate init
- Deduction guides for containers
  - Requires iterator traits
- Map
  - Sorted insert
  - Add missing methods
- Unordered Map
- Pair/Tuple
  - Tuple Size
  - Write tests
- Set
- Testing
  - Sanitizer build in CI
  - CppCheck
- Type Traits
  - float
- Vector
  - Add examples
- Misc
  - Swap
  - Hash
