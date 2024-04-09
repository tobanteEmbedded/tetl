// SPDX-License-Identifier: BSL-1.0

#include <etl/strings.hpp>

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/string_view.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    using namespace etl::detail;
    using namespace etl::literals;
    using namespace etl::strings;

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

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
