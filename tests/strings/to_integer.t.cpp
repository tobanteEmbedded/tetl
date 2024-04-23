// SPDX-License-Identifier: BSL-1.0

#include <etl/strings.hpp>

#include <etl/array.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

namespace {

template <typename Int>
constexpr auto test() -> bool
{
    using namespace etl::string_view_literals;
    using namespace etl::strings;

    CHECK(to_integer<Int>({}, 10).end == nullptr);
    CHECK(to_integer<Int>({}, 10).error == to_integer_error::invalid_input);

    {
        auto str    = ""_sv;
        auto result = to_integer<Int>(str, 10);
        CHECK(result.end == str.begin());
        CHECK(result.error == to_integer_error::invalid_input);
    }
    {
        auto str    = "$"_sv;
        auto result = to_integer<Int>(str, 10);
        CHECK(result.end == str.begin());
        CHECK(result.error == to_integer_error::invalid_input);
    }

    {
        auto str    = "Z"_sv;
        auto result = to_integer<Int>(str, 10);
        CHECK(result.end == str.begin());
        CHECK(result.error == to_integer_error::invalid_input);
    }

    {
        auto str    = "z"_sv;
        auto result = to_integer<Int>(str, 10);
        CHECK(result.end == str.begin());
        CHECK(result.error == to_integer_error::invalid_input);
    }

    {
        auto str    = "A"_sv;
        auto result = to_integer<Int>(str, 16);
        CHECK(result.error == to_integer_error::none);
        CHECK(result.end == str.end());
        CHECK(result.value == Int(10));
    }

    {
        auto str    = "a"_sv;
        auto result = to_integer<Int>(str, 16);
        CHECK(result.error == to_integer_error::none);
        CHECK(result.end == str.end());
        CHECK(result.value == Int(10));
    }

    {
        auto str    = "B"_sv;
        auto result = to_integer<Int>(str, 16);
        CHECK(result.error == to_integer_error::none);
        CHECK(result.end == str.end());
        CHECK(result.value == Int(11));
    }

    {
        auto str    = "b"_sv;
        auto result = to_integer<Int>(str, 16);
        CHECK(result.error == to_integer_error::none);
        CHECK(result.end == str.end());
        CHECK(result.value == Int(11));
    }

    {
        auto str    = "F"_sv;
        auto result = to_integer<Int>(str, 16);
        CHECK(result.error == to_integer_error::none);
        CHECK(result.end == str.end());
        CHECK(result.value == Int(15));
    }

    {
        auto str    = "G"_sv;
        auto result = to_integer<Int>(str, 16);
        CHECK(result.error == to_integer_error::invalid_input);
        CHECK(result.end == str.data());
    }

    if constexpr (etl::is_same_v<Int, signed char>) {
        auto legal = "127"_sv;
        CHECK(to_integer<Int>(legal, 10).value == Int(127));
        CHECK(to_integer<Int>(legal, 10).error == to_integer_error::none);

        auto overflow = "128"_sv;
        CHECK(to_integer<Int>(overflow, 10).end == overflow.begin());
        CHECK(to_integer<Int>(overflow, 10).error == to_integer_error::overflow);
    }

    if constexpr (sizeof(Int) < 4) {
        auto number = "99999"_sv;
        CHECK(to_integer<Int>(number, 10).end == number.begin());
        CHECK(to_integer<Int>(number, 10).error == to_integer_error::overflow);
    }

    auto test = [](auto str, auto expected) -> bool {
        auto const res = to_integer<Int>(str, 10);
        CHECK(res.error == to_integer_error::none);
        CHECK(res.value == static_cast<Int>(expected));
        return true;
    };

    CHECK(test("0"_sv, 0));
    CHECK(test("  0"_sv, 0));

    CHECK(test("10"_sv, 10));
    CHECK(test("99"_sv, 99));

    if constexpr (sizeof(Int) >= 4) {
        CHECK(test("  1111"_sv, 1111));
        CHECK(test("123456789"_sv, 123456789));
        CHECK(test("   123456789"_sv, 123456789));
    }

    if constexpr (etl::is_signed_v<Int>) {
        CHECK(test("-10"_sv, -10));
        CHECK(test("-99"_sv, -99));
        CHECK(test("  -42"_sv, -42));

        if constexpr (sizeof(Int) >= 4) {
            CHECK(test("-999"_sv, -999));
            CHECK(test("-123456789"_sv, -123456789));
            CHECK(test("   -123456789"_sv, -123456789));
        }
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
