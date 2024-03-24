// SPDX-License-Identifier: BSL-1.0

#include <etl/meta.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

namespace {
constexpr auto test_all() -> bool
{
    using etl::meta::at_t;
    using etl::meta::cons_t;
    using etl::meta::head_t;
    using etl::meta::list;
    using etl::meta::tail_t;

    CHECK_SAME_TYPE(head_t<list<int, long>>, int);
    CHECK_SAME_TYPE(head_t<list<float, long>>, float);

    CHECK_SAME_TYPE(tail_t<list<int, long>>, list<long>);
    CHECK_SAME_TYPE(tail_t<list<float, char, long>>, list<char, long>);

    CHECK_SAME_TYPE(cons_t<int, list<>>, list<int>);
    CHECK_SAME_TYPE(cons_t<int, list<long>>, list<int, long>);
    CHECK_SAME_TYPE(cons_t<int, list<long, float>>, list<int, long, float>);

    CHECK_SAME_TYPE(at_t<0, list<int>>, int);
    CHECK_SAME_TYPE(at_t<0, list<int, long, double>>, int);
    CHECK_SAME_TYPE(at_t<1, list<int, long, double>>, long);
    CHECK_SAME_TYPE(at_t<2, list<int, long, double>>, double);

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
