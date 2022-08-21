/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/bit.hpp"

#include "etl/cstdint.hpp"

#include "testing/testing.hpp"

constexpr auto test_byteswap_u8() -> bool
{
    using etl::uint8_t;
    assert(etl::byteswap(uint8_t { 0 }) == uint8_t { 0 });
    assert(etl::byteswap(uint8_t { 1 }) == uint8_t { 1 });
    assert(etl::byteswap(uint8_t { 2 }) == uint8_t { 2 });
    assert(etl::byteswap(uint8_t { 3 }) == uint8_t { 3 });
    assert(etl::byteswap(uint8_t { 100 }) == uint8_t { 100 });
    assert(etl::byteswap(uint8_t { 255 }) == uint8_t { 255 });
    return true;
}

constexpr auto test_byteswap_u16() -> bool
{
    using etl::uint16_t;
    assert(etl::byteswap(uint16_t { 0 }) == uint16_t { 0 });
    assert(etl::byteswap(uint16_t { 0x00AA }) == uint16_t { 0xAA00 });
    assert(etl::byteswap(uint16_t { 0xCAFE }) == uint16_t { 0xFECA });
    return true;
}

constexpr auto test_byteswap_u32() -> bool
{
    using etl::uint32_t;
    assert(etl::byteswap(uint32_t { 0 }) == uint32_t { 0 });
    assert(etl::byteswap(0xDEADBEEFU) == 0xEFBEADDEU);
    return true;
}

constexpr auto test_byteswap_u64() -> bool
{
    using etl::uint64_t;
    assert(etl::byteswap(etl::uint64_t { 0 }) == etl::uint64_t { 0 });
    assert(etl::byteswap(0x0123456789ABCDEFULL) == 0xEFCDAB8967452301ULL);
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test_byteswap_u8());
    assert(test_byteswap_u16());
    assert(test_byteswap_u32());
    assert(test_byteswap_u64());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
