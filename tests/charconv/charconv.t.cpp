// SPDX-License-Identifier: BSL-1.0

#include <etl/charconv.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/string.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

constexpr auto test_chars_format() -> bool
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
    return true;
}

constexpr auto test_to_chars_result() -> bool
{
    {
        auto lhs = etl::to_chars_result{nullptr, etl::errc{}};
        auto rhs = etl::to_chars_result{nullptr, etl::errc{}};
        CHECK(lhs == rhs);
    }

    {
        char buffer[16] = {};
        auto lhs        = etl::to_chars_result{buffer, etl::errc{}};
        auto rhs        = etl::to_chars_result{buffer, etl::errc{}};
        CHECK(lhs == rhs);

        CHECK(lhs != etl::to_chars_result{nullptr, etl::errc{}});
        CHECK(lhs != etl::to_chars_result{buffer, etl::errc::value_too_large});

        CHECK(etl::to_chars_result{nullptr, etl::errc{}} != rhs);
        CHECK(etl::to_chars_result{buffer, etl::errc::value_too_large} != rhs);
    }

    return true;
}

constexpr auto test_from_chars_result() -> bool
{
    {
        auto lhs = etl::from_chars_result{nullptr, etl::errc{}};
        auto rhs = etl::from_chars_result{nullptr, etl::errc{}};
        CHECK(lhs == rhs);
    }

    {
        char buffer[16] = {};
        auto lhs        = etl::from_chars_result{buffer, etl::errc{}};
        auto rhs        = etl::from_chars_result{buffer, etl::errc{}};
        CHECK(lhs == rhs);

        CHECK(lhs != etl::from_chars_result{nullptr, etl::errc{}});
        CHECK(lhs != etl::from_chars_result{buffer, etl::errc::invalid_argument});
        CHECK(lhs != etl::from_chars_result{buffer, etl::errc::result_out_of_range});

        CHECK(etl::from_chars_result{nullptr, etl::errc{}} != rhs);
        CHECK(etl::from_chars_result{buffer, etl::errc::invalid_argument} != rhs);
        CHECK(etl::from_chars_result{buffer, etl::errc::result_out_of_range} != rhs);
    }

    return true;
}

template <typename T>
constexpr auto test_from_chars() -> bool
{
    using namespace etl::string_view_literals;

    {
        auto val = T{};

        auto foo = "foo"_sv;
        CHECK_FALSE(static_cast<bool>(etl::from_chars(foo.begin(), foo.end(), val)));
        CHECK(etl::from_chars(foo.begin(), foo.end(), val).ptr == foo.data());
        CHECK(etl::from_chars(foo.begin(), foo.end(), val).ec == etl::errc::invalid_argument);

        auto minus = "-"_sv;
        CHECK_FALSE(static_cast<bool>(etl::from_chars(minus.begin(), minus.end(), val)));
        CHECK(etl::from_chars(minus.begin(), minus.end(), val).ptr == minus.data());
        CHECK(etl::from_chars(minus.begin(), minus.end(), val).ec == etl::errc::invalid_argument);

        auto plus = "+"_sv;
        CHECK_FALSE(static_cast<bool>(etl::from_chars(plus.begin(), plus.end(), val)));
        CHECK(etl::from_chars(plus.begin(), plus.end(), val).ptr == plus.data());
        CHECK(etl::from_chars(plus.begin(), plus.end(), val).ec == etl::errc::invalid_argument);

        auto fourfoo      = "4foo"_sv;
        auto const result = etl::from_chars(fourfoo.begin(), fourfoo.end(), val);
        CHECK(bool{result});
        CHECK(result.ptr == etl::next(fourfoo.data()));
        CHECK(result.ec == etl::errc{});
        CHECK(val == T(4));
    }

    auto test = [](auto tc, T expected, int base) -> bool {
        auto val          = T{};
        auto const result = etl::from_chars(tc.begin(), tc.end(), val, base);
        CHECK(bool{result});
        CHECK(val == expected);
        return true;
    };

    CHECK(test("1"_sv, 1, 2));
    CHECK(test("1"_sv, 1, 10));
    CHECK(test("1"_sv, 1, 16));

    CHECK(test("2"_sv, 2, 10));
    CHECK(test("10"_sv, 10, 10));
    CHECK(test("42"_sv, 42, 10));
    CHECK(test("99"_sv, 99, 10));
    CHECK(test("126"_sv, 126, 10));
    CHECK(test("126 "_sv, 126, 10));
    CHECK(test("126A"_sv, 126, 10));

    if constexpr (sizeof(T) > 1) {
        CHECK(test("1000"_sv, 1000, 10));
        CHECK(test("9999"_sv, 9999, 10));
        CHECK(test("A0"_sv, 160, 16));
        CHECK(test("a0"_sv, 160, 16));
        CHECK(test("a0 "_sv, 160, 16));
        CHECK(test("a0Z"_sv, 160, 16));
    }

    if constexpr (etl::is_signed_v<T>) {
        CHECK(test("-1"_sv, -1, 10));
        CHECK(test("-2"_sv, -2, 10));
        CHECK(test("-10"_sv, -10, 10));
        CHECK(test("-42"_sv, -42, 10));
        CHECK(test("-99"_sv, -99, 10));
        CHECK(test("-126"_sv, -126, 10));

        if constexpr (sizeof(T) > 1) {
            CHECK(test("-1000"_sv, -1000, 10));
            CHECK(test("-9999"_sv, -9999, 10));
        }
    }

    if constexpr (etl::is_same_v<T, etl::int8_t>) {
        {
            auto val          = T{};
            auto const str    = "-128"_sv;
            auto const result = etl::from_chars(str.begin(), str.end(), val);
            CHECK(bool{result});
            CHECK(val == T(-128));
            CHECK(result.ptr == str.end());
            CHECK(result.ec == etl::errc{});
        }

        {
            auto val          = T{};
            auto const str    = "127"_sv;
            auto const result = etl::from_chars(str.begin(), str.end(), val);
            CHECK(bool{result});
            CHECK(val == T(127));
            CHECK(result.ptr == str.end());
            CHECK(result.ec == etl::errc{});
        }

        {
            auto val          = T{};
            auto const str    = "128"_sv;
            auto const result = etl::from_chars(str.begin(), str.end(), val);
            CHECK_FALSE(bool{result});
            CHECK(result.ptr == str.data());
            CHECK(result.ec == etl::errc::result_out_of_range);
        }

        {
            auto val          = T{};
            auto const str    = "-129"_sv;
            auto const result = etl::from_chars(str.begin(), str.end(), val);
            CHECK_FALSE(bool{result});
            CHECK(result.ptr == str.data());
            CHECK(result.ec == etl::errc::result_out_of_range);
        }
    }

    return true;
}

template <typename T>
constexpr auto test_to_chars() -> bool
{
    using namespace etl::string_view_literals;

    auto test = [](T tc, etl::string_view expected) {
        auto buf          = etl::array<char, 16>{};
        auto const result = etl::to_chars(buf.begin(), buf.end(), tc, 10);
        CHECK(bool{result});
        CHECK(result.ptr != nullptr);
        CHECK(buf.data() == expected);
        return true;
    };

    CHECK(test(1, "1"_sv));
    CHECK(test(2, "2"_sv));
    CHECK(test(10, "10"_sv));
    CHECK(test(42, "42"_sv));
    CHECK(test(99, "99"_sv));
    CHECK(test(126, "126"_sv));

    if constexpr (sizeof(T) > 1) {
        CHECK(test(1000, "1000"_sv));
        CHECK(test(9999, "9999"_sv));
    }

    if constexpr (etl::is_signed_v<T>) {
        CHECK(test(-1, "-1"_sv));
        CHECK(test(-2, "-2"_sv));
        CHECK(test(-10, "-10"_sv));
        CHECK(test(-42, "-42"_sv));
        CHECK(test(-99, "-99"_sv));
        CHECK(test(-126, "-126"_sv));

        if constexpr (sizeof(T) > 1) {
            CHECK(test(-1000, "-1000"_sv));
            CHECK(test(-9999, "-9999"_sv));
        }
    }

    // overflow
    auto buf          = etl::array<char, 3>{};
    auto const result = etl::to_chars(buf.begin(), buf.end(), 9999, 10);
    CHECK_FALSE(bool{result});
    CHECK(result.ec == etl::errc::value_too_large);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test_chars_format());
    CHECK(test_to_chars_result());
    CHECK(test_from_chars_result());

    CHECK(test_from_chars<char>());
    CHECK(test_from_chars<signed char>());
    CHECK(test_from_chars<signed short>());
    CHECK(test_from_chars<signed int>());
    CHECK(test_from_chars<signed long>());
    CHECK(test_from_chars<signed long long>());
    CHECK(test_from_chars<unsigned char>());
    CHECK(test_from_chars<unsigned short>());
    CHECK(test_from_chars<unsigned int>());
    CHECK(test_from_chars<unsigned long>());
    CHECK(test_from_chars<unsigned long long>());

    CHECK(test_to_chars<char>());
    CHECK(test_to_chars<signed char>());
    CHECK(test_to_chars<signed short>());
    CHECK(test_to_chars<signed int>());
    CHECK(test_to_chars<signed long>());
    CHECK(test_to_chars<signed long long>());
    CHECK(test_to_chars<unsigned char>());
    CHECK(test_to_chars<unsigned short>());
    CHECK(test_to_chars<unsigned int>());
    CHECK(test_to_chars<unsigned long>());
    CHECK(test_to_chars<unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
