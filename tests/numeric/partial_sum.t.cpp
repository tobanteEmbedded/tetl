// SPDX-License-Identifier: BSL-1.0

#include <etl/numeric.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // // plus
    // {
    //     etl::static_vector<T, 5> vec { 5, T { 2 } };
    //     etl::partial_sum(vec.begin(), vec.end(), vec.begin());
    //     assert(vec[0] == T { 2 });
    //     assert(vec[1] == T { 4 });
    //     assert(vec[2] == T { 6 });
    //     assert(vec[3] == T { 8 });
    // }

    // // multiplies (pow2)
    // {
    //     etl::static_vector<T, 5> vec { 5, T { 2 } };
    //     etl::partial_sum(begin(vec), end(vec), begin(vec),
    //     etl::multiplies<>()); assert(vec[0] == T { 2 }); assert(vec[1] == T {
    //     4 }); assert(vec[2] == T { 8 }); assert(vec[3] == T { 16 });
    // }
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
