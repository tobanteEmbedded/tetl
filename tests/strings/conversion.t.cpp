// SPDX-License-Identifier: BSL-1.0

#include <etl/strings.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

using namespace etl::literals;
using namespace etl::strings;
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

constexpr auto test_all() -> bool
{
    CHECK(test_integer_to_string());

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
