// SPDX-License-Identifier: BSL-1.0

#include <etl/strings.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/string_view.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

template <typename Float>
constexpr auto test() -> bool
{
    using namespace etl::strings;
    using namespace etl::string_view_literals;

    auto test = [](Float in, auto precision, auto out) -> bool {
        auto buf = etl::array<char, 12>{};
        auto res = from_floating_point(in, buf, precision);
        CHECK(res.error == from_floating_point_error::none);
        CHECK(etl::string_view{buf.data()} == out);
        return true;
    };

    CHECK(test(Float(233.007), 0, "233"_sv));
    CHECK(test(Float(233.007), 1, "233.0"_sv));
    CHECK(test(Float(233.007), 2, "233.00"_sv));
    CHECK(test(Float(233.007), 3, "233.007"_sv));
    CHECK(test(Float(233.007), 4, "233.0070"_sv));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test<float>());
    STATIC_CHECK(test<double>());
    STATIC_CHECK(test<long double>());
    return 0;
}
