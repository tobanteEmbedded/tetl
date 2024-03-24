// SPDX-License-Identifier: BSL-1.0

#include <etl/meta.hpp>

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

namespace {
constexpr auto test_all() -> bool
{
    using etl::meta::list;

    CHECK_SAME_TYPE(etl::meta::head_t<list<int, long>>, int);
    CHECK_SAME_TYPE(etl::meta::head_t<list<float, long>>, float);

    CHECK_SAME_TYPE(etl::meta::tail_t<list<int, long>>, list<long>);
    CHECK_SAME_TYPE(etl::meta::tail_t<list<float, char, long>>, list<char, long>);

    CHECK_SAME_TYPE(etl::meta::push_back_t<int, list<>>, list<int>);
    CHECK_SAME_TYPE(etl::meta::push_back_t<int, list<long>>, list<long, int>);
    CHECK_SAME_TYPE(etl::meta::push_back_t<int, list<long, float>>, list<long, float, int>);

    CHECK_SAME_TYPE(etl::meta::push_front_t<int, list<>>, list<int>);
    CHECK_SAME_TYPE(etl::meta::push_front_t<int, list<long>>, list<int, long>);
    CHECK_SAME_TYPE(etl::meta::push_front_t<int, list<long, float>>, list<int, long, float>);

    CHECK_SAME_TYPE(etl::meta::at_t<0, list<int>>, int);
    CHECK_SAME_TYPE(etl::meta::at_t<0, list<int, long, double>>, int);
    CHECK_SAME_TYPE(etl::meta::at_t<1, list<int, long, double>>, long);
    CHECK_SAME_TYPE(etl::meta::at_t<2, list<int, long, double>>, double);

    CHECK(etl::meta::contains_v<int, list<int>>);
    CHECK(etl::meta::contains_v<int, list<int, long, double>>);
    CHECK(etl::meta::contains_v<int, list<long, int, double>>);
    CHECK(etl::meta::contains_v<int, list<double, long, int>>);
    CHECK_FALSE(etl::meta::contains_v<char, list<double, long, int>>);
    CHECK_FALSE(etl::meta::contains_v<int, list<>>);

    CHECK(etl::meta::count_v<int, list<>> == 0);
    CHECK(etl::meta::count_v<int, list<char>> == 0);
    CHECK(etl::meta::count_v<int, list<char, long>> == 0);

    CHECK(etl::meta::count_v<int, list<int>> == 1);
    CHECK(etl::meta::count_v<int, list<int, long, double>> == 1);
    CHECK(etl::meta::count_v<int, list<char, int, double>> == 1);
    CHECK(etl::meta::count_v<int, list<int, long, double, int>> == 2);

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
