<!-- SPDX-License-Identifier: BSL-1.0 -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch -->

# Design

## Builtin Types

|       **Type**       | AVR | MSP430 | ARM32 | Unix ARM32/X86 | Unix ARM64/X64 | Win ARM64/X64 |
| :------------------: | :-: | :----: | :---: | :------------: | :------------: | :-----------: |
|   `unsigned char`    |  1  |   1    |   1   |       1        |       1        |       1       |
|   `unsigned short`   |  2  |   2    |   2   |       2        |       2        |       2       |
|    `unsigned int`    |  2  |   2    |   4   |       4        |       4        |       4       |
|   `unsigned long`    |  4  |   4    |   4   |       4        |       8        |       4       |
| `unsigned long long` |  8  |   8    |   8   |       8        |       8        |       8       |
|       `float`        |  4  |   4    |   4   |       4        |       4        |       4       |
|       `double`       |  4  |   8    |   8   |       8        |       8        |       8       |
|    `long double`     |  8  |   8    |   8   |       16       |       16       |       8       |
|        `char`        |  1  |   1    |   1   |       1        |       1        |       1       |
|      `wchar_t`       |  2  |   4    |   4   |       4        |       4        |       2       |
|      `char8_t`       |  1  |   1    |   1   |       1        |       1        |       1       |
|      `char16_t`      |  2  |   2    |   2   |       2        |       2        |       2       |
|      `char32_t`      |  4  |   4    |   4   |       4        |       4        |       4       |

- **Unix:** Linux, macOS, BSD and WebAssembly

### AVR

Size of `double` and `long double` can be changed with `-mdouble=bits` and `-mlong-double=bits`. Possible values are `32` and `64`.

## Issues

### Forced to use namesapce std

- `std::construct_at`
  - Only way to get constexpr "placement new"
- tuple protocol (structured bindings)
  - `std::tuple_size`
  - `std::tuple_element`
- three-way comparison
  - `operator<=>` returns a type from `std` for builtin types
