# tobanteAudio - ETL

Embedded template library intended for micro controller where the STL is not available. This library does not depend on the `Arduino.h` header.

```sh
git clone https://github.com/tobanteAudio/taetl.git
```

## Status

|                                                           LICENSE                                                           |                                                      Linux / macOS                                                      |                                                                  Windows                                                                  | Documentation |
| :-------------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------------------------: | :-----------: |
| [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) | [![Build Status](https://travis-ci.org/tobanteAudio/taetl.svg?branch=master)](https://travis-ci.org/tobanteAudio/taetl) | [![AppVeyor Build status](https://img.shields.io/appveyor/ci/tobanteAudio/taetl.svg)](https://ci.appveyor.com/project/tobanteAudio/taetl) |  **Doxygen**  |

## Goals

- 100% portable
- Modern C++ (17)
- Replacement for the STL
- No dynamic memory
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

## Install

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
     taetl@0.1.0
     # Semantic Versioning Rules
     taetl@^0.1.0
     taetl@~0.1.0
     taetl@>=0.1.0
```

#### CLI

```sh
# Using library Id
platformio lib install 6337

# Using library Name
platformio lib install "taetl"

# Install specific version
platformio lib install 6337@0.1.0
platformio lib install "taetl@0.1.0"
```

### Arduino IDE

Coming soon...

## Examples

### Build on Desktop

```sh
cd $PROJECT_ROOT
mkdir build && cd build
cmake ..
cmake --build  .
```

## ToDo

- Algorithm
- Type Traits
  - float
- CI
  - AppVeyor
  - AVR-GCC
