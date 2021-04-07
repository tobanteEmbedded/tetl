# All The Headers

## Overview

|            Header             |         Library          |       Status       |                   Source                    |                     Tests                      |     Comments      |
| :---------------------------: | :----------------------: | :----------------: | :-----------------------------------------: | :--------------------------------------------: | :---------------: |
|    [algorithm](#algorithm)    |        Algorithms        | :heavy_check_mark: |    [algorithm.hpp](../etl/algorithm.hpp)    |    [algorithm](../tests/test_algorithm.cpp)    |                   |
|            [any]()            |         Utility          |        :x:         |                                             |                                                |                   |
|        [array](#array)        |        Container         | :heavy_check_mark: |        [array.hpp](../etl/array.hpp)        |        [array](../tests/test_array.cpp)        |                   |
|          [bit](#bit)          |         Numeric          | :heavy_check_mark: |          [bit.hpp](../etl/bit.hpp)          |          [bit](../tests/test_bit.cpp)          |                   |
|       [bitset](#bitset)       |         Utility          | :heavy_check_mark: |       [bitset.hpp](../etl/bitset.hpp)       |       [bitset](../tests/test_bitset.cpp)       |                   |
|      [cassert](#cassert)      | Utility / Error Handling | :heavy_check_mark: |      [cassert.hpp](../etl/cassert.hpp)      |      [cassert](../tests/test_cassert.cpp)      |                   |
|       [cctype](#cctype)       |         Strings          | :heavy_check_mark: |       [cctype.hpp](../etl/cctype.hpp)       |       [cctype](../tests/test_cctype.cpp)       |                   |
|          [cerrno]()           | Utility / Error Handling |        :x:         |                                             |                                                |                   |
|       [cfloat](#cfloat)       | Utility / Numeric Limits | :heavy_check_mark: |       [cfloat.hpp](../etl/cfloat.hpp)       |       [cfloat](../tests/test_cfloat.cpp)       |                   |
|     [charconv](#charconv)     |         Strings          | :heavy_check_mark: |     [charconv.hpp](../etl/charconv.hpp)     |     [charconv](../tests/test_charconv.cpp)     |                   |
|       [chrono](#chrono)       |         Utility          | :heavy_check_mark: |       [chrono.hpp](../etl/chrono.hpp)       |       [chrono](../tests/test_chrono.cpp)       |                   |
|         [cinttypes]()         | Utility / Numeric Limits |        :x:         |                                             |                                                |       TODO        |
|      [climits](#climits)      | Utility / Numeric Limits | :heavy_check_mark: |      [climits.hpp](../etl/climits.hpp)      |      [climits](../tests/test_climits.cpp)      |                   |
|        [cmath](#cmath)        |         Numeric          | :heavy_check_mark: |        [cmath.hpp](../etl/cmath.hpp)        |        [cmath](../tests/test_cmath.cpp)        |                   |
|          [compare]()          |         Utility          |        :x:         |                                             |                                                |       TODO        |
|     [concepts](#concepts)     |         Concepts         | :heavy_check_mark: |     [concepts.hpp](../etl/concepts.hpp)     |     [concepts](../tests/test_concepts.cpp)     |                   |
|         [coroutine]()         |        Coroutines        |        :x:         |                                             |                                                |                   |
|         [crtp](#crtp)         |         Utility          | :heavy_check_mark: |         [crtp.hpp](../etl/crtp.hpp)         |         [crtp](../tests/test_crtp.cpp)         |   Not standard.   |
|          [csetjmp]()          |         Utility          |        :x:         |                                             |                                                |                   |
|          [csignal]()          |         Utility          |        :x:         |                                             |                                                |                   |
|          [cstdarg]()          |         Utility          |        :x:         |                                             |                                                |                   |
|      [cstddef](#cstddef)      |         Utility          | :heavy_check_mark: |      [cstddef.hpp](../etl/cstddef.hpp)      |      [cstddef](../tests/test_cstddef.cpp)      |                   |
|      [cstdint](#cstdint)      | Utility / Numeric Limits | :heavy_check_mark: |      [cstdint.hpp](../etl/cstdint.hpp)      |      [cstdint](../tests/test_cstdint.cpp)      |                   |
|       [cstdio](#cstdio)       |         Utility          | :heavy_check_mark: |       [cstdio.hpp](../etl/cstdio.hpp)       |       [cstdio](../tests/test_cstdio.cpp)       |                   |
|      [cstdlib](#cstdlib)      |         Utility          | :heavy_check_mark: |      [cstdlib.hpp](../etl/cstdlib.hpp)      |      [cstdlib](../tests/test_cstdlib.cpp)      |                   |
|      [cstring](#cstring)      |         Strings          | :heavy_check_mark: |      [cstring.hpp](../etl/cstring.hpp)      |      [cstring](../tests/test_cstring.cpp)      |                   |
|        [ctime](#ctime)        |         Utility          | :heavy_check_mark: |        [ctime.hpp](../etl/ctime.hpp)        |        [ctime](../tests/test_ctime.cpp)        |                   |
|         [exception]()         | Utility / Error Handling |        :x:         |                                             |                                                |                   |
|     [expected](#expected)     | Utility / Error Handling | :heavy_check_mark: |     [expected.hpp](../etl/expected.hpp)     |     [expected](../tests/test_expected.cpp)     | Not standard yet. |
|       [format](#format)       |         Strings          | :heavy_check_mark: |       [format.hpp](../etl/format.hpp)       |       [format](../tests/test_format.cpp)       |                   |
|   [functional](#functional)   |         Utility          | :heavy_check_mark: |   [functional.hpp](../etl/functional.hpp)   |   [functional](../tests/test_functional.cpp)   |                   |
|     [initializer_list]()      |                          |        :x:         |                                             |                                                |                   |
|          [ios](#ios)          |       Input/Output       | :heavy_check_mark: |          [ios.hpp](../etl/ios.hpp)          |          [ios](../tests/test_ios.cpp)          |                   |
|     [iterator](#iterator)     |         Iterator         | :heavy_check_mark: |     [iterator.hpp](../etl/iterator.hpp)     |     [iterator](../tests/test_iterator.cpp)     |                   |
|       [limits](#limits)       | Utility / Numeric Limits | :heavy_check_mark: |       [limits.hpp](../etl/limits.hpp)       |       [limits](../tests/test_limits.cpp)       |                   |
|          [map](#map)          |        Container         | :heavy_check_mark: |          [map.hpp](../etl/map.hpp)          |          [map](../tests/test_map.cpp)          |                   |
|       [memory](#memory)       | Utility / Dynamic Memory | :heavy_check_mark: |       [memory.hpp](../etl/memory.hpp)       |       [memory](../tests/test_memory.cpp)       |                   |
|      [memory_resource]()      | Utility / Dynamic Memory |        :x:         |                                             |                                                |                   |
|        [mutex](#mutex)        |      Thread Support      | :heavy_check_mark: |        [mutex.hpp](../etl/mutex.hpp)        |        [mutex](../tests/test_mutex.cpp)        |                   |
|          [new](#new)          | Utility / Dynamic Memory | :heavy_check_mark: |          [new.hpp](../etl/new.hpp)          |          [new](../tests/test_new.cpp)          |                   |
|      [numbers](#numbers)      |         Numeric          | :heavy_check_mark: |      [numbers.hpp](../etl/numbers.hpp)      |      [numbers](../tests/test_numbers.cpp)      |                   |
|      [numeric](#numeric)      |         Numeric          | :heavy_check_mark: |      [numeric.hpp](../etl/numeric.hpp)      |      [numeric](../tests/test_numeric.cpp)      |                   |
|     [optional](#optional)     |         Utility          | :heavy_check_mark: |     [optional.hpp](../etl/optional.hpp)     |     [optional](../tests/test_optional.cpp)     |                   |
|        [ratio](#ratio)        |         Numeric          | :heavy_check_mark: |        [ratio.hpp](../etl/ratio.hpp)        |        [ratio](../tests/test_ratio.cpp)        |                   |
|     [scoped_allocator]()      | Utility / Dynamic Memory |        :x:         |                                             |                                                |                   |
|  [scope_guard](#scope_guard)  |         Utility          | :heavy_check_mark: |  [scope_guard.hpp](../etl/scope_guard.hpp)  |  [scope_guard](../tests/test_scope_guard.cpp)  | Not standard yet. |
|      [source_location]()      |         Utility          |        :x:         |                                             |                                                |                   |
|          [set](#set)          |        Container         | :heavy_check_mark: |          [set.hpp](../etl/set.hpp)          |          [set](../tests/test_set.cpp)          |                   |
|         [span](#span)         |        Container         | :heavy_check_mark: |         [span.hpp](../etl/span.hpp)         |         [span](../tests/test_span.cpp)         |                   |
|        [stack](#stack)        |        Container         | :heavy_check_mark: |        [stack.hpp](../etl/stack.hpp)        |        [stack](../tests/test_stack.cpp)        |                   |
|        [stack_trace]()        |         Utility          |        :x:         |                                             |                                                |                   |
|         [stdexcept]()         | Utility / Error Handling |        :x:         |                                             |                                                |                   |
|       [string](#string)       |         Strings          | :heavy_check_mark: |       [string.hpp](../etl/string.hpp)       |       [string](../tests/test_string.cpp)       |                   |
|  [string_view](#string_view)  |         Strings          | :heavy_check_mark: |  [string_view.hpp](../etl/string_view.hpp)  |  [string_view](../tests/test_string_view.cpp)  |                   |
| [system_error](#system_error) | Utility / Error Handling | :heavy_check_mark: | [system_error.hpp](../etl/system_error.hpp) | [system_error](../tests/test_system_error.cpp) |                   |
|        [tuple](#tuple)        |         Utility          | :heavy_check_mark: |        [tuple.hpp](../etl/tuple.hpp)        |        [tuple](../tests/test_tuple.cpp)        |                   |
|        [type_index]()         |         Utility          |        :x:         |                                             |                                                |                   |
|         [type_info]()         |         Utility          |        :x:         |                                             |                                                |                   |
|  [type_traits](#type_traits)  |         Utility          | :heavy_check_mark: |  [type_traits.hpp](../etl/type_traits.hpp)  |  [type_traits](../tests/test_type_traits.cpp)  |                   |
|      [utility](#utility)      |         Utility          | :heavy_check_mark: |      [utility.hpp](../etl/utility.hpp)      |      [utility](../tests/test_utility.cpp)      |                   |
|      [variant](#variant)      |         Utility          | :heavy_check_mark: |      [variant.hpp](../etl/variant.hpp)      |      [variant](../tests/test_variant.cpp)      |                   |
|       [vector](#vector)       |        Container         | :heavy_check_mark: |       [vector.hpp](../etl/vector.hpp)       |       [vector](../tests/test_vector.cpp)       |                   |
|      [version](#version)      |         Utility          | :heavy_check_mark: |      [version.hpp](../etl/version.hpp)      |      [version](../tests/test_version.cpp)      |                   |
|      [warning](#warning)      |         Utility          | :heavy_check_mark: |      [warning.hpp](../etl/warning.hpp)      |      [warning](../tests/test_warning.cpp)      |   Not standard.   |

## Detail

### algorithm

### array

### bit

### bitset

### cassert

### cctype

### cfloat

### charconv

### chrono

### climits

### cmath

### concepts

### crtp

### cstddef

### cstdint

### cstdio

### cstdlib

### cstring

### ctime

### expected

### format

### functional

### ios

### iterator

### limits

### map

### memory

### mutex

### new

### numbers

### numeric

### optional

### ratio

### scope_guard

### set

### span

### stack

### string

### string_view

### system_error

### tuple

### type_traits

### utility

### variant

### vector

### version

### warning
