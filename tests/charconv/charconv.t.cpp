/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/charconv.hpp"

#include "etl/array.hpp"
#include "etl/iterator.hpp"
#include "etl/string.hpp"
#include "etl/string_view.hpp"
#include "etl/type_traits.hpp"

#include "testing/testing.hpp"

constexpr auto test_chars_format() -> bool
{
    assert(etl::chars_format::scientific != etl::chars_format::hex);
    assert(etl::chars_format::scientific != etl::chars_format::fixed);
    assert(etl::chars_format::scientific != etl::chars_format::general);

    assert(etl::chars_format::hex != etl::chars_format::scientific);
    assert(etl::chars_format::hex != etl::chars_format::fixed);
    assert(etl::chars_format::hex != etl::chars_format::general);

    assert(etl::chars_format::fixed != etl::chars_format::scientific);
    assert(etl::chars_format::fixed != etl::chars_format::hex);
    assert(etl::chars_format::fixed != etl::chars_format::general);

    assert(etl::chars_format::general != etl::chars_format::scientific);
    assert(etl::chars_format::general != etl::chars_format::hex);
    assert(etl::chars_format::general != etl::chars_format::fixed);
    return true;
}

constexpr auto test_to_chars_result() -> bool
{
    {
        auto lhs = etl::to_chars_result { nullptr, etl::errc {} };
        auto rhs = etl::to_chars_result { nullptr, etl::errc {} };
        assert(lhs == rhs);
    }

    {
        char buffer[16] = {};
        auto lhs        = etl::to_chars_result { buffer, etl::errc {} };
        auto rhs        = etl::to_chars_result { buffer, etl::errc {} };
        assert(lhs == rhs);
    }

    return true;
}

constexpr auto test_from_chars_result() -> bool
{
    {
        auto lhs = etl::from_chars_result { nullptr, etl::errc {} };
        auto rhs = etl::from_chars_result { nullptr, etl::errc {} };
        assert(lhs == rhs);
    }

    {
        char buffer[16] = {};
        auto lhs        = etl::from_chars_result { buffer, etl::errc {} };
        auto rhs        = etl::from_chars_result { buffer, etl::errc {} };
        assert(lhs == rhs);
    }

    return true;
}

template <typename T>
constexpr auto test_from_chars() -> bool
{
    using string_t = etl::static_string<16>;

    auto test = [](string_t tc, T expected) -> void {
        auto val          = T {};
        auto const result = etl::from_chars(tc.begin(), tc.end(), val);
        assert(result.ptr == tc.end());
        assert(val == expected);
    };

    test("1", 1);
    test(" 1", 1);
    test("  1", 1);
    test("   1", 1);
    test("    1", 1);

    test("2", 2);
    test("10", 10);
    test("42", 42);
    test("99", 99);
    test("126", 126);

    if constexpr (sizeof(T) > 1) {
        test("1000", 1000);
        test("9999", 9999);
    }

    if constexpr (etl::is_signed_v<T>) {
        test("-1", -1);
        test("-2", -2);
        test("-10", -10);
        test("-42", -42);
        test("-99", -99);
        test("-126", -126);

        if constexpr (sizeof(T) > 1) {
            test("-1000", -1000);
            test("-9999", -9999);
        }
    }
    return true;
}

template <typename T>
constexpr auto test_to_chars() -> bool
{
    using string_t = etl::static_string<16>;

    auto test = [](T tc, string_t expected) -> void {
        auto buf          = etl::array<char, 16> {};
        auto const result = etl::to_chars(buf.begin(), buf.end(), tc, 10);
        assert(result.ptr != nullptr);
        assert(etl::string_view { buf.data() } == expected);
    };

    test(1, "1");
    test(2, "2");
    test(10, "10");
    test(42, "42");
    test(99, "99");
    test(126, "126");

    if constexpr (sizeof(T) > 1) {
        test(1000, "1000");
        test(9999, "9999");
    }

    if constexpr (etl::is_signed_v<T>) {
        test(-1, "-1");
        test(-2, "-2");
        test(-10, "-10");
        test(-42, "-42");
        test(-99, "-99");
        test(-126, "-126");

        if constexpr (sizeof(T) > 1) {
            test(-1000, "-1000");
            test(-9999, "-9999");
        }
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test_chars_format());
    assert(test_to_chars_result());
    assert(test_from_chars_result());

    assert(test_from_chars<char>());
    assert(test_from_chars<unsigned char>());
    assert(test_from_chars<signed char>());

    assert(test_from_chars<unsigned short>());
    assert(test_from_chars<short>());

    assert(test_from_chars<unsigned int>());
    assert(test_from_chars<int>());

    assert(test_from_chars<unsigned long>());
    assert(test_from_chars<long>());

    assert(test_from_chars<unsigned long long>());
    assert(test_from_chars<long long>());

    assert(test_to_chars<char>());
    assert(test_to_chars<unsigned char>());
    assert(test_to_chars<signed char>());

    assert(test_to_chars<unsigned short>());
    assert(test_to_chars<short>());

    assert(test_to_chars<unsigned int>());
    assert(test_to_chars<int>());

    assert(test_to_chars<unsigned long>());
    assert(test_to_chars<long>());

    assert(test_to_chars<unsigned long long>());
    assert(test_to_chars<long long>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
