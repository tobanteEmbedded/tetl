// SPDX-License-Identifier: BSL-1.0

#include <etl/bit.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

constexpr auto test_8bit() -> bool
{
    using etl::uint8_t;

    CHECK_NOEXCEPT(etl::byteswap(uint8_t{0}));
    CHECK_SAME_TYPE(decltype(etl::byteswap(uint8_t{0})), uint8_t);

    CHECK(etl::byteswap(uint8_t{0}) == uint8_t{0});
    CHECK(etl::byteswap(uint8_t{1}) == uint8_t{1});
    CHECK(etl::byteswap(uint8_t{2}) == uint8_t{2});
    CHECK(etl::byteswap(uint8_t{3}) == uint8_t{3});
    CHECK(etl::byteswap(uint8_t{100}) == uint8_t{100});
    CHECK(etl::byteswap(uint8_t{255}) == uint8_t{255});

    return true;
}

constexpr auto test_16bit() -> bool
{
    using etl::uint16_t;

    CHECK_NOEXCEPT(etl::byteswap(uint16_t{0}));
    CHECK_SAME_TYPE(decltype(etl::byteswap(uint16_t{0})), uint16_t);

    CHECK(etl::byteswap(uint16_t{0}) == uint16_t{0});
    CHECK(etl::byteswap(uint16_t{0x00AA}) == uint16_t{0xAA00});
    CHECK(etl::byteswap(uint16_t{0xCAFE}) == uint16_t{0xFECA});

    CHECK(etl::detail::byteswap_fallback(uint16_t{0}) == uint16_t{0});
    CHECK(etl::detail::byteswap_fallback(uint16_t{0x00AA}) == uint16_t{0xAA00});
    CHECK(etl::detail::byteswap_fallback(uint16_t{0xCAFE}) == uint16_t{0xFECA});

    return true;
}

constexpr auto test_32bit() -> bool
{
    using etl::uint32_t;

    CHECK_NOEXCEPT(etl::byteswap(uint32_t{0}));
    CHECK_SAME_TYPE(decltype(etl::byteswap(uint32_t{0})), uint32_t);

    CHECK(etl::byteswap(uint32_t{0}) == uint32_t{0});
    CHECK(etl::byteswap(0xDEADBEEFU) == 0xEFBEADDEU);

    CHECK(etl::detail::byteswap_fallback(uint32_t{0}) == uint32_t{0});
    CHECK(etl::detail::byteswap_fallback(uint32_t{0xDEADBEEFU}) == uint32_t{0xEFBEADDEU});

    return true;
}

constexpr auto test_64bit() -> bool
{
    using etl::uint64_t;

    CHECK_NOEXCEPT(etl::byteswap(uint64_t{0}));
    CHECK_SAME_TYPE(decltype(etl::byteswap(uint64_t{0})), uint64_t);

    CHECK(etl::byteswap(uint64_t{0}) == uint64_t{0});
    CHECK(etl::byteswap(0x0123456789ABCDEFULL) == 0xEFCDAB8967452301ULL);

    CHECK(etl::detail::byteswap_fallback(uint64_t{0}) == uint64_t{0});
    CHECK(etl::detail::byteswap_fallback(uint64_t{0x0123456789ABCDEFULL}) == uint64_t{0xEFCDAB8967452301ULL});

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test_8bit());
    CHECK(test_16bit());
    CHECK(test_32bit());
    CHECK(test_64bit());

    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<signed char>(0))), signed char);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<signed short>(0))), signed short);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<signed int>(0))), signed int);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<signed long>(0))), signed long);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<signed long long>(0))), signed long long);

    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned char>(0))), unsigned char);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned short>(0))), unsigned short);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned int>(0))), unsigned int);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned long>(0))), unsigned long);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<unsigned long long>(0))), unsigned long long);

    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<bool>(0))), bool);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<char>(0))), char);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<char8_t>(0))), char8_t);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<char16_t>(0))), char16_t);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<char32_t>(0))), char32_t);
    CHECK_SAME_TYPE(decltype(etl::byteswap(static_cast<wchar_t>(0))), wchar_t);

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    static_assert(test_all());
    return 0;
}
