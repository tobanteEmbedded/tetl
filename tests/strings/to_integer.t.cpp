// SPDX-License-Identifier: BSL-1.0

#include <etl/strings.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

namespace {
template <typename Int>
constexpr auto test_string_to_integer() -> bool
{
    using namespace etl::string_view_literals;
    using namespace etl::strings;

    CHECK(to_integer(nullptr, 0, 10).end == nullptr);
    CHECK(to_integer(nullptr, 0, 10).error == to_integer_error::invalid_input);

    auto null = etl::array{'\0'};
    CHECK(to_integer(null.data(), null.size(), 10).end == null.data());
    CHECK(to_integer(null.data(), null.size(), 10).error == to_integer_error::invalid_input);

    auto test = [](auto str, auto expected) -> bool {
        auto const res = to_integer<Int>(str.data(), str.size(), 10);
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

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
