# tobanteAudio - ETL

Embedded template library intended for micro controller where the STL is not available. This library does not depend on the `Arduino.h` header.

## Goals

- 100% portable
- Replacement for the STL
- No dynamic memory
- Arduino IDE / PlatformIO compatible
- Easy desktop development (cmake)

## Install

The following steps explain how to add `taetl` to your project. Embedded or desktop.

### CMake

Add `taetl` as a git submodule or plain folder, then add these lines to your `CMakeLists.txt`:

```cmake
add_subdirectory(${PATH_TO_TAETL})
target_link_libraries(${YOUR_TARGET} tobanteAudio::etl)
```

### Arduino IDE

Coming soon...

### PlatformIO

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

- Container
  - Array
- Algorithm
- Type Traits
  - float
- CI
  - Travis
  - AppVeyor
  - AVR-GCC
