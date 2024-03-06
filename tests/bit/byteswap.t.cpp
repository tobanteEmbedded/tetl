// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

constexpr auto test_byteswap_u8() -> bool
{
    using etl::uint8_t;
    assert(etl::byteswap(uint8_t {0}) == uint8_t {0});
    assert(etl::byteswap(uint8_t {1}) == uint8_t {1});
    assert(etl::byteswap(uint8_t {2}) == uint8_t {2});
    assert(etl::byteswap(uint8_t {3}) == uint8_t {3});
    assert(etl::byteswap(uint8_t {100}) == uint8_t {100});
    assert(etl::byteswap(uint8_t {255}) == uint8_t {255});

    return true;
}

constexpr auto test_byteswap_u16() -> bool
{
    using etl::uint16_t;
    assert(etl::byteswap(uint16_t {0}) == uint16_t {0});
    assert(etl::byteswap(uint16_t {0x00AA}) == uint16_t {0xAA00});
    assert(etl::byteswap(uint16_t {0xCAFE}) == uint16_t {0xFECA});

    assert(etl::detail::byteswap_u16_fallback(uint16_t {0}) == uint16_t {0});
    assert(etl::detail::byteswap_u16_fallback(uint16_t {0x00AA}) == uint16_t {0xAA00});
    assert(etl::detail::byteswap_u16_fallback(uint16_t {0xCAFE}) == uint16_t {0xFECA});
    return true;
}

constexpr auto test_byteswap_u32() -> bool
{
    using etl::uint32_t;
    assert(etl::byteswap(uint32_t {0}) == uint32_t {0});
    assert(etl::byteswap(0xDEADBEEFU) == 0xEFBEADDEU);

    assert(etl::detail::byteswap_u32_fallback(uint32_t {0}) == uint32_t {0});
    assert(etl::detail::byteswap_u32_fallback(0xDEADBEEFU) == 0xEFBEADDEU);

    return true;
}

constexpr auto test_byteswap_u64() -> bool
{
    using etl::uint64_t;
    assert(etl::byteswap(etl::uint64_t {0}) == etl::uint64_t {0});
    assert(etl::byteswap(0x0123456789ABCDEFULL) == 0xEFCDAB8967452301ULL);

    assert(etl::detail::byteswap_u64_fallback(etl::uint64_t {0}) == etl::uint64_t {0});
    assert(etl::detail::byteswap_u64_fallback(0x0123456789ABCDEFULL) == 0xEFCDAB8967452301ULL);
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
