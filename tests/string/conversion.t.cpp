/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cstdint.hpp"
#include "etl/iterator.hpp"
#include "etl/system_error.hpp"
#include "etl/type_traits.hpp"

#include "etl/_strings/conversion.hpp"

#include "etl/string_view.hpp"

#include "testing/approx.hpp"
#include "testing/testing.hpp"

using namespace etl::literals;
using namespace etl::detail;

template <typename T>
constexpr auto test_floats() -> bool
{
    assert(approx(ascii_to_floating_point<T>("0"), T(0.0)));
    assert(approx(ascii_to_floating_point<T>("10"), T(10.0)));
    assert(approx(ascii_to_floating_point<T>("100.0"), T(100.0)));
    assert(approx(ascii_to_floating_point<T>("1000.000"), T(1000.0)));
    assert(approx(ascii_to_floating_point<T>("10000"), T(10000.0)));
    assert(approx(ascii_to_floating_point<T>("999999.0"), T(999999.0)));
    assert(approx(ascii_to_floating_point<T>("9999999"), T(9999999.0)));
    return true;
}

constexpr auto test_int() -> bool
{
    auto test = [](int in, auto out) -> bool {
        char buf[12] = {};
        auto res     = int_to_ascii(in, etl::begin(buf), 10, sizeof(buf));
        assert(res.error == int_to_ascii_error::none);
        assert(etl::string_view { buf } == out);
        return true;
    };

    assert(test(0, "0"_sv));
    assert(test(10, "10"_sv));
    assert(test(-10, "-10"_sv));
    assert(test(99, "99"_sv));
    assert(test(-99, "-99"_sv));
    assert(test(143, "143"_sv));
    assert(test(999, "999"_sv));
    assert(test(-999, "-999"_sv));
    assert(test(1111, "1111"_sv));

    if constexpr (sizeof(int) >= 4) {
        assert(test(123456789, "123456789"_sv));
        assert(test(-123456789, "-123456789"_sv));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test_int());
    assert(test_floats<float>());
    assert(test_floats<double>());
    assert(test_floats<long double>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}