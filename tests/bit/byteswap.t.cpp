// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

constexpr auto test_8bit() -> bool
{
    using etl::uint8_t;

    ASSERT_NOEXCEPT(etl::byteswap(uint8_t{0}));
    ASSERT_SAME_TYPE(decltype(etl::byteswap(uint8_t{0})), uint8_t);

    ASSERT(etl::byteswap(uint8_t{0}) == uint8_t{0});
    ASSERT(etl::byteswap(uint8_t{1}) == uint8_t{1});
    ASSERT(etl::byteswap(uint8_t{2}) == uint8_t{2});
    ASSERT(etl::byteswap(uint8_t{3}) == uint8_t{3});
    ASSERT(etl::byteswap(uint8_t{100}) == uint8_t{100});
    ASSERT(etl::byteswap(uint8_t{255}) == uint8_t{255});

    return true;
}

constexpr auto test_16bit() -> bool
{
    using etl::uint16_t;

    ASSERT_NOEXCEPT(etl::byteswap(uint16_t{0}));
    ASSERT_SAME_TYPE(decltype(etl::byteswap(uint16_t{0})), uint16_t);

    ASSERT(etl::byteswap(uint16_t{0}) == uint16_t{0});
    ASSERT(etl::byteswap(uint16_t{0x00AA}) == uint16_t{0xAA00});
    ASSERT(etl::byteswap(uint16_t{0xCAFE}) == uint16_t{0xFECA});

    ASSERT(etl::detail::byteswap_fallback(uint16_t{0}) == uint16_t{0});
    ASSERT(etl::detail::byteswap_fallback(uint16_t{0x00AA}) == uint16_t{0xAA00});
    ASSERT(etl::detail::byteswap_fallback(uint16_t{0xCAFE}) == uint16_t{0xFECA});

    return true;
}

constexpr auto test_32bit() -> bool
{
    using etl::uint32_t;

    ASSERT_NOEXCEPT(etl::byteswap(uint32_t{0}));
    ASSERT_SAME_TYPE(decltype(etl::byteswap(uint32_t{0})), uint32_t);

    ASSERT(etl::byteswap(uint32_t{0}) == uint32_t{0});
    ASSERT(etl::byteswap(0xDEADBEEFU) == 0xEFBEADDEU);

    ASSERT(etl::detail::byteswap_fallback(uint32_t{0}) == uint32_t{0});
    ASSERT(etl::detail::byteswap_fallback(uint32_t{0xDEADBEEFU}) == uint32_t{0xEFBEADDEU});

    return true;
}

constexpr auto test_64bit() -> bool
{
    using etl::uint64_t;

    ASSERT_NOEXCEPT(etl::byteswap(uint64_t{0}));
    ASSERT_SAME_TYPE(decltype(etl::byteswap(uint64_t{0})), uint64_t);

    ASSERT(etl::byteswap(uint64_t{0}) == uint64_t{0});
    ASSERT(etl::byteswap(0x0123456789ABCDEFULL) == 0xEFCDAB8967452301ULL);

    ASSERT(etl::detail::byteswap_fallback(uint64_t{0}) == uint64_t{0});
    ASSERT(etl::detail::byteswap_fallback(uint64_t{0x0123456789ABCDEFULL}) == uint64_t{0xEFCDAB8967452301ULL});

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(test_8bit());
    ASSERT(test_16bit());
    ASSERT(test_32bit());
    ASSERT(test_64bit());

    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<signed char>(0))), signed char);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<signed short>(0))), signed short);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<signed int>(0))), signed int);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<signed long>(0))), signed long);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<signed long long>(0))), signed long long);

    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned char>(0))), unsigned char);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned short>(0))), unsigned short);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned int>(0))), unsigned int);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned long>(0))), unsigned long);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned long long>(0))), unsigned long long);

    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<bool>(0))), bool);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<char>(0))), char);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<char8_t>(0))), char8_t);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<char16_t>(0))), char16_t);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<char32_t>(0))), char32_t);
    ASSERT_SAME_TYPE(decltype(etl::byteswap(static_cast<wchar_t>(0))), wchar_t);

    return true;
}

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());
    return 0;
}
