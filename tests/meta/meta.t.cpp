// SPDX-License-Identifier: BSL-1.0

#include <etl/meta.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

namespace {
constexpr auto test_all() -> bool
{
    using etl::meta::at;
    using etl::meta::head;
    using etl::meta::list;
    using etl::meta::push_front;
    using etl::meta::tail;

    CHECK_SAME_TYPE(head<list<int, long>>, int);
    CHECK_SAME_TYPE(head<list<float, long>>, float);

    CHECK_SAME_TYPE(tail<list<int, long>>, list<long>);
    CHECK_SAME_TYPE(tail<list<float, char, long>>, list<char, long>);

    CHECK_SAME_TYPE(push_front<int, list<>>, list<int>);
    CHECK_SAME_TYPE(push_front<int, list<long>>, list<int, long>);
    CHECK_SAME_TYPE(push_front<int, list<long, float>>, list<int, long, float>);

    CHECK_SAME_TYPE(at<0, list<int>>, int);
    CHECK_SAME_TYPE(at<0, list<int, long, double>>, int);
    CHECK_SAME_TYPE(at<1, list<int, long, double>>, long);
    CHECK_SAME_TYPE(at<2, list<int, long, double>>, double);

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
