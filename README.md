# TAETL

The tobanteAudio embedded template library is intended for micro controller where the `STL` is not available. Designed to have a similar API. This library supports `AVR/Arduino` micro controllers.

```sh
git clone https://github.com/tobanteAudio/taetl.git
```

## Status

|                                                           LICENSE                                                           |                                                      Linux / macOS                                                      |                                                                  Windows                                                                  |                                                                  AVR                                                                  |                                    Issues                                     |                                                         Code Coverage                                                          |                                                                                                                          Codacy                                                                                                                           |
| :-------------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------: | :----------------------------------------------------------------------------------------------------------------------------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) | [![Build Status](https://travis-ci.org/tobanteAudio/taetl.svg?branch=master)](https://travis-ci.org/tobanteAudio/taetl) | [![AppVeyor Build status](https://img.shields.io/appveyor/ci/tobanteAudio/taetl.svg)](https://ci.appveyor.com/project/tobanteAudio/taetl) | [![Cirrus CI Build Status](https://api.cirrus-ci.com/github/tobanteAudio/taetl.svg)](https://cirrus-ci.com/github/tobanteAudio/taetl) | ![GitHub issues](https://img.shields.io/github/issues/tobanteAudio/taetl.svg) | [![codecov](https://codecov.io/gh/tobanteAudio/taetl/branch/master/graph/badge.svg)](https://codecov.io/gh/tobanteAudio/taetl) | [![Codacy Badge](https://api.codacy.com/project/badge/Grade/80518b423ad649649e782a3773d4e17b)](https://app.codacy.com/app/tobanteAudio/taetl?utm_source=github.com&utm_medium=referral&utm_content=tobanteAudio/taetl&utm_campaign=Badge_Grade_Dashboard) |

## Table of Contents

1. [Intro](#taetl)
2. [Status](#status)
3. [Design Goals](#design-goals)
4. [Documentation](#documentation)
5. [Project Integration](#project-integration)
   - [CMake](#cmake)
   - [PlatformIO](#platformio)
   - [Arduino IDE](#arduino-ide)
   - [Avr-gcc](#avr-gcc)
6. [Examples](#examples)
7. [Usage](#usage)
   - [Algorithm](#algorithm)
   - [Array](#array)
   - [Numeric](#numeric)
   - [String](#string)
   - [Type Traits](#type-traits)
8. [ToDo](#todo)

## Design Goals

- 100% portable
- Modern C++17
- Similar api to the STL
- No dynamic memory
- `constexpr` all the things
- Arduino IDE / PlatformIO compatible
- Easy desktop development (cmake)

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

The following steps explain how to add `taetl` to your project. Embedded or desktop.

### CMake

Add `taetl` as a git submodule or plain folder, then add these lines to your `CMakeLists.txt`:

```sh
cd $YOUR_CMAKE_PROJECT
mkdir 3rd_party
git submodule add https://github.com/tobanteAudio/taetl.git 3rd_party/taetl
```

```cmake
add_subdirectory(${PATH_TO_TAETL})
target_link_libraries(${YOUR_TARGET} tobanteAudio::etl)
```

### PlatformIO

#### platformio.ini

```ini
[env:myenv]
platform = atmelavr
framework = arduino
build_flags = -std=c++17
lib_deps =
     # Using library Id
     6337

     # Using library Name
     taetl

     # Depend on specific version
     taetl@0.2.0
     # Semantic Versioning Rules
     taetl@^0.2.0
     taetl@~0.2.0
     taetl@>=0.2.0
```

#### CLI

```sh
# Using library Id
platformio lib install 6337

# Using library Name
platformio lib install "taetl"

# Install specific version
platformio lib install 6337@0.2.0
platformio lib install "taetl@0.2.0"
```

### Arduino IDE

Coming soon...

### Avr-gcc

An example on how to build the `algorithm.cpp` file with `avr-gcc`. C++17 is required.

```sh
cd $PROJECT_ROOT
avr-gcc --std=c++17 -O3 -Wall -Wextra -o example_algorithm -Isrc examples/algorithm.cpp
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

Below are some simple examples for most of the headers in `taetl`. For more detailed examples look at the `examples` subdirectory. Building the [documentation](#documentation) with `Doxygen` will give details about the complete API.

### Algorithm

```cpp
// C STANDARD
#include <stdio.h>

// TAETL
#include "taetl/algorithm.hpp"
#include "taetl/array.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::Array<double, 16> t_array;

    // Add elements to the back
    t_array.push_back(1.0);
    t_array.push_back(2.0);
    t_array.push_back(3.0);
    t_array.push_back(4.0);


    auto print = [](auto& x) { printf("%f\n", x); };

    // FOR_EACH
    taetl::for_each(t_array.begin(), t_array.end(), print);
    // FOR_EACH_N with lambda
    taetl::for_each_n(t_array.begin(), 3,
                      [](const auto& x) { printf("%f\n", x * 2); });
}
```

### Array

```cpp
// TAETL
#include "taetl/array.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::Array<int, 16> t_array;

    // Add 2 elements to the back
    t_array.push_back(1);
    t_array.push_back(2);


    for (auto& item : t_array)
    {
        printf("%d", item);
    }

    return 0;
}
```

### Numeric

```cpp
// C STANDARD
#include <stdio.h>

// TAETL
#include "taetl/array.hpp"
#include "taetl/numeric.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::Array<double, 16> t_array;

    // Add elements to the back
    t_array.push_back(1.0);
    t_array.push_back(2.0);
    t_array.push_back(3.0);
    t_array.push_back(4.0);

    // ACCUMULATE
    auto sum = taetl::accumulate(t_array.begin(), t_array.end(), 0.0);

    printf("%f", sum);

    return 0;
}
```

### String

```cpp
// C STANDARD
#include <stdio.h>
// TAETL
#include "taetl/string.hpp"

int main()
{
    // Create array with capacity of 16 and size of 0
    taetl::String<char, 16> t_string{};

    const char* cptr = "C-string";
    t_string.append(cptr, 4);

    printf("\"%s\"\n", t_string.c_str());

    for (auto& c : t_string)
    {
        printf("%c", c);
    }

    printf("\nSize: %zu\n", t_string.size());
    printf("Length: %zu\n", t_string.length());
    printf("Capacity: %zu\n", t_string.capacity());

    return 0;
}
```

### Type Traits

```cpp
// C STANDARD
#include <stdio.h>

// TAETL
#include "taetl/array.hpp"
#include "taetl/type_traits.hpp"

template <typename T>
typename taetl::enable_if<taetl::is_integral<T>::value, int>::type func(T val)
{
    return val;
}

float func(float val) { return val; }

int main()
{
    taetl::Array<int, 16> t_array;

    t_array.push_back(1);
    t_array.push_back(2);

    for (auto& item : t_array)
    {
        func(item);
    }

    func(uint16_t{1});
    func(3.0f);  // Does not call template
    return 0;
}
```

## ToDo

- README
  - Simple Examples
- Examples
  - Hardware Pins (PORT & ID)
- Type Traits
  - float
- CI
  - AVR-GCC
