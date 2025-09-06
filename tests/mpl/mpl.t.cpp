// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/mpl.hpp>
    #include <etl/type_traits.hpp>
#endif

namespace {
constexpr auto test_all() -> bool
{
    using etl::mpl::list;

    CHECK_SAME_TYPE(etl::mpl::head_t<list<int, long>>, int);
    CHECK_SAME_TYPE(etl::mpl::head_t<list<float, long>>, float);

    CHECK_SAME_TYPE(etl::mpl::tail_t<list<int, long>>, list<long>);
    CHECK_SAME_TYPE(etl::mpl::tail_t<list<float, char, long>>, list<char, long>);

    CHECK_SAME_TYPE(etl::mpl::push_back_t<int, list<>>, list<int>);
    CHECK_SAME_TYPE(etl::mpl::push_back_t<int, list<long>>, list<long, int>);
    CHECK_SAME_TYPE(etl::mpl::push_back_t<int, list<long, float>>, list<long, float, int>);

    CHECK_SAME_TYPE(etl::mpl::push_front_t<int, list<>>, list<int>);
    CHECK_SAME_TYPE(etl::mpl::push_front_t<int, list<long>>, list<int, long>);
    CHECK_SAME_TYPE(etl::mpl::push_front_t<int, list<long, float>>, list<int, long, float>);

    CHECK_SAME_TYPE(etl::mpl::at_t<0, list<int>>, int);
    CHECK_SAME_TYPE(etl::mpl::at_t<0, list<int, long, double>>, int);
    CHECK_SAME_TYPE(etl::mpl::at_t<1, list<int, long, double>>, long);
    CHECK_SAME_TYPE(etl::mpl::at_t<2, list<int, long, double>>, double);

    CHECK(etl::mpl::contains_v<int, list<int>>);
    CHECK(etl::mpl::contains_v<int, list<int, long, double>>);
    CHECK(etl::mpl::contains_v<int, list<long, int, double>>);
    CHECK(etl::mpl::contains_v<int, list<double, long, int>>);
    CHECK_FALSE(etl::mpl::contains_v<char, list<double, long, int>>);
    CHECK_FALSE(etl::mpl::contains_v<int, list<>>);

    CHECK(etl::mpl::count_v<int, list<>> == 0);
    CHECK(etl::mpl::count_v<int, list<char>> == 0);
    CHECK(etl::mpl::count_v<int, list<char, long>> == 0);

    CHECK(etl::mpl::count_v<int, list<int>> == 1);
    CHECK(etl::mpl::count_v<int, list<int, long, double>> == 1);
    CHECK(etl::mpl::count_v<int, list<char, int, double>> == 1);
    CHECK(etl::mpl::count_v<int, list<int, long, double, int>> == 2);

    CHECK(etl::mpl::index_of_v<int, list<int>> == 0);
    CHECK(etl::mpl::index_of_v<int, list<float, int>> == 1);
    CHECK(etl::mpl::index_of_v<float, list<float, int>> == 0);

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
