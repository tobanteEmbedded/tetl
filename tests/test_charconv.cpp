/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/charconv.hpp"

#include "etl/array.hpp"
#include "etl/iterator.hpp"
#include "etl/string.hpp"
#include "etl/string_view.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("charconv: chars_format", "[charconv]")
{
    CHECK(etl::chars_format::scientific != etl::chars_format::hex);
    CHECK(etl::chars_format::scientific != etl::chars_format::fixed);
    CHECK(etl::chars_format::scientific != etl::chars_format::general);

    CHECK(etl::chars_format::hex != etl::chars_format::scientific);
    CHECK(etl::chars_format::hex != etl::chars_format::fixed);
    CHECK(etl::chars_format::hex != etl::chars_format::general);

    CHECK(etl::chars_format::fixed != etl::chars_format::scientific);
    CHECK(etl::chars_format::fixed != etl::chars_format::hex);
    CHECK(etl::chars_format::fixed != etl::chars_format::general);

    CHECK(etl::chars_format::general != etl::chars_format::scientific);
    CHECK(etl::chars_format::general != etl::chars_format::hex);
    CHECK(etl::chars_format::general != etl::chars_format::fixed);
}

TEST_CASE("charconv: to_chars_result", "[charconv]")
{
    SECTION("default")
    {
        auto lhs = etl::to_chars_result { nullptr, etl::errc {} };
        auto rhs = etl::to_chars_result { nullptr, etl::errc {} };
        CHECK(lhs == rhs);
    }

    SECTION("char buffer")
    {
        char buffer[16] = {};
        auto lhs        = etl::to_chars_result { buffer, etl::errc {} };
        auto rhs        = etl::to_chars_result { buffer, etl::errc {} };
        CHECK(lhs == rhs);
    }
}

TEST_CASE("charconv: from_chars_result", "[charconv]")
{
    SECTION("default")
    {
        auto lhs = etl::from_chars_result { nullptr, etl::errc {} };
        auto rhs = etl::from_chars_result { nullptr, etl::errc {} };
        CHECK(lhs == rhs);
    }

    SECTION("char buffer")
    {
        char buffer[16] = {};
        auto lhs        = etl::from_chars_result { buffer, etl::errc {} };
        auto rhs        = etl::from_chars_result { buffer, etl::errc {} };
        CHECK(lhs == rhs);
    }
}

TEMPLATE_TEST_CASE("charconv: from_chars<Integer>", "[charconv]", char,
    unsigned char, signed char, unsigned short, short, unsigned int, int,
    unsigned long, long, unsigned long long, long long)
{
    using string_t = etl::static_string<16>;

    auto test = [](string_t tc, TestType expected) -> void {
        auto val          = TestType {};
        auto const result = etl::from_chars(tc.begin(), tc.end(), val);
        CHECK(result.ptr == tc.end());
        CHECK(val == expected);
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

    if constexpr (sizeof(TestType) > 1) {
        test("1000", 1000);
        test("9999", 9999);
    }

    if constexpr (etl::is_signed_v<TestType>) {
        test("-1", -1);
        test("-2", -2);
        test("-10", -10);
        test("-42", -42);
        test("-99", -99);
        test("-126", -126);

        if constexpr (sizeof(TestType) > 1) {
            test("-1000", -1000);
            test("-9999", -9999);
        }
    }
}

TEMPLATE_TEST_CASE("charconv: to_chars<Integer>", "[charconv]", char,
    unsigned char, signed char, unsigned short, short, unsigned int, int,
    unsigned long, long, unsigned long long, long long)
{
    using string_t = etl::static_string<16>;

    auto test = [](TestType tc, string_t expected) -> void {
        auto buf          = etl::array<char, 16> {};
        auto const result = etl::to_chars(buf.begin(), buf.end(), tc, 10);
        CHECK(result.ptr != nullptr);
        CHECK(etl::string_view { buf.data() } == expected);
    };

    test(1, "1");
    test(2, "2");
    test(10, "10");
    test(42, "42");
    test(99, "99");
    test(126, "126");

    if constexpr (sizeof(TestType) > 1) {
        test(1000, "1000");
        test(9999, "9999");
    }

    if constexpr (etl::is_signed_v<TestType>) {
        test(-1, "-1");
        test(-2, "-2");
        test(-10, "-10");
        test(-42, "-42");
        test(-99, "-99");
        test(-126, "-126");

        if constexpr (sizeof(TestType) > 1) {
            test(-1000, "-1000");
            test(-9999, "-9999");
        }
    }
}
