// SPDX-License-Identifier: BSL-1.0

#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

namespace {
constexpr auto test_all() -> bool
{
    CHECK_SAME_TYPE(etl::head_t<etl::type_sequence<int, long>>, int);
    CHECK_SAME_TYPE(etl::head_t<etl::type_sequence<float, long>>, float);

    CHECK_SAME_TYPE(etl::tail_t<etl::type_sequence<int, long>>, etl::type_sequence<long>);
    CHECK_SAME_TYPE(etl::tail_t<etl::type_sequence<float, char, long>>, etl::type_sequence<char, long>);

    CHECK_SAME_TYPE(etl::cons_t<int, etl::type_sequence<>>, etl::type_sequence<int>);
    CHECK_SAME_TYPE(etl::cons_t<int, etl::type_sequence<long>>, etl::type_sequence<int, long>);
    CHECK_SAME_TYPE(etl::cons_t<int, etl::type_sequence<long, float>>, etl::type_sequence<int, long, float>);

    CHECK_SAME_TYPE(etl::nth_type_t<0, etl::type_sequence<int>>, int);
    CHECK_SAME_TYPE(etl::nth_type_t<0, etl::type_sequence<int, long, double>>, int);
    CHECK_SAME_TYPE(etl::nth_type_t<1, etl::type_sequence<int, long, double>>, long);
    CHECK_SAME_TYPE(etl::nth_type_t<2, etl::type_sequence<int, long, double>>, double);

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
