// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstdint.hpp>
    #include <etl/numeric.hpp>
    #include <etl/vector.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    // // plus
    // {
    //     etl::static_vector<T, 5> vec { 5, T { 2 } };
    //     etl::partial_sum(vec.begin(), vec.end(), vec.begin());
    //     CHECK(vec[0] == T { 2 });
    //     CHECK(vec[1] == T { 4 });
    //     CHECK(vec[2] == T { 6 });
    //     CHECK(vec[3] == T { 8 });
    // }

    // // multiplies (pow2)
    // {
    //     etl::static_vector<T, 5> vec { 5, T { 2 } };
    //     etl::partial_sum(begin(vec), end(vec), begin(vec),
    //     etl::multiplies<>()); CHECK(vec[0] == T { 2 }); CHECK(vec[1] == T {
    //     4 }); CHECK(vec[2] == T { 8 }); CHECK(vec[3] == T { 16 });
    // }
    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
