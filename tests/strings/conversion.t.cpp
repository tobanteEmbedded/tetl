// SPDX-License-Identifier: BSL-1.0

#include <etl/_strings/conversion.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

using namespace etl::literals;
using namespace etl::detail;

template <typename T>
constexpr auto test_floats() -> bool
{
    CHECK_APPROX(string_to_floating_point<T>("0"), T(0.0));
    CHECK_APPROX(string_to_floating_point<T>("10"), T(10.0));
    CHECK_APPROX(string_to_floating_point<T>("100.0"), T(100.0));
    CHECK_APPROX(string_to_floating_point<T>("1000.000"), T(1000.0));
    CHECK_APPROX(string_to_floating_point<T>("10000"), T(10000.0));
    CHECK_APPROX(string_to_floating_point<T>("999999.0"), T(999999.0));
    CHECK_APPROX(string_to_floating_point<T>("9999999"), T(9999999.0));
    CHECK_APPROX(string_to_floating_point<T>("   9999999"), T(9999999.0));
    return true;
}

constexpr auto test_integer_to_string() -> bool
{
    auto test = [](int in, auto out) -> bool {
        char buf[12] = {};
        auto res     = integer_to_string(in, etl::begin(buf), 10, sizeof(buf));
        CHECK(res.error == integer_to_string_error::none);
        CHECK(etl::string_view{buf} == out);
        return true;
    };

    CHECK(test(0, "0"_sv));
    CHECK(test(10, "10"_sv));
    CHECK(test(-10, "-10"_sv));
    CHECK(test(99, "99"_sv));
    CHECK(test(-99, "-99"_sv));
    CHECK(test(143, "143"_sv));
    CHECK(test(999, "999"_sv));
    CHECK(test(-999, "-999"_sv));
    CHECK(test(1111, "1111"_sv));

    if constexpr (sizeof(int) >= 4) {
        CHECK(test(123456789, "123456789"_sv));
        CHECK(test(-123456789, "-123456789"_sv));
    }

    return true;
}

template <typename Int>
constexpr auto test_string_to_integer() -> bool
{
    CHECK(string_to_integer(nullptr, 0, 10).end == nullptr);
    CHECK(string_to_integer(nullptr, 0, 10).error == string_to_integer_error::invalid_input);

    auto null = etl::array{'\0'};
    CHECK(string_to_integer(null.data(), null.size(), 10).end == null.data());
    CHECK(string_to_integer(null.data(), null.size(), 10).error == string_to_integer_error::invalid_input);

    auto test = [](auto str, auto expected) -> bool {
        auto const res = string_to_integer<Int>(str.data(), str.size(), 10);
        CHECK(res.error == string_to_integer_error::none);
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
        CHECK(test("-999"_sv, -999));
        CHECK(test("  -42"_sv, -42));

        if constexpr (sizeof(Int) >= 4) {
            CHECK(test("-123456789"_sv, -123456789));
            CHECK(test("   -123456789"_sv, -123456789));
        }
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test_integer_to_string());

    CHECK(test_string_to_integer<signed char>());
    CHECK(test_string_to_integer<signed short>());
    CHECK(test_string_to_integer<signed int>());
    CHECK(test_string_to_integer<signed long>());
    CHECK(test_string_to_integer<signed long long>());

    CHECK(test_string_to_integer<unsigned char>());
    CHECK(test_string_to_integer<unsigned short>());
    CHECK(test_string_to_integer<unsigned int>());
    CHECK(test_string_to_integer<unsigned long>());
    CHECK(test_string_to_integer<unsigned long long>());

    CHECK(test_floats<float>());
    CHECK(test_floats<double>());
    CHECK(test_floats<long double>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
