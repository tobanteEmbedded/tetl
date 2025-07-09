// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.array;
import etl.cstddef;
import etl.iterator;
import etl.string_view;
import etl.strings;
#else
    #include <etl/array.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/iterator.hpp>
    #include <etl/string_view.hpp>
    #include <etl/strings.hpp>
#endif

static constexpr auto test() -> bool
{
    using namespace etl::literals;
    using namespace etl::strings;

    auto test = [](int in, auto out) -> bool {
        char buf[12] = {};
        auto res     = from_integer(in, etl::data(buf), etl::size(buf), 10);
        CHECK(res.error == from_integer_error::none);
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

    CHECK(from_integer(0, nullptr, 0, 10).error == from_integer_error::overflow);

    auto buf = etl::array<char, 1>{};
    CHECK(from_integer(123, buf.data(), buf.size(), 10).error == from_integer_error::overflow);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
