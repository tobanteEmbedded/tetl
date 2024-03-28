# Roadmap

## Features

### Ranges

- `common_reference`: Needed for a lot of concepts

## Testing

### QEMU

- Run unit test & examples on QEMU emulations.
- Via `CMAKE_CROSSCOMPILING_EMULATOR`
  - For Emscripten this is set to `node` in the CMake toolchain file

### clang-verify

Test that static assertion fire when they should.

- [libcxx: midpoint.verify.cpp](https://github.com/llvm/llvm-project/blob/main/libcxx/test/std/numerics/numeric.ops/numeric.ops.midpoint/midpoint.verify.cpp)

```cpp
// test.cpp
#include <etl/array.hpp>

// expected-error@*:* {{static assertion failed due to requirement '2UL < 2UL': array index out of range}}
auto v = etl::get<2>(etl::array<int, 2>{}); // expected-note {{in instantiation of function template specialization 'etl::get<2UL, int, 2UL>' requested here}}
```

```sh
clang -Xclang -verify -c -std=c++20 -Iinclude test.cpp
```
