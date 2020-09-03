# Project Integration

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
add_subdirectory(3rd_party/taetl EXCLUDE_FROM_ALL)
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
