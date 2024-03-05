// SPDX-License-Identifier: BSL-1.0

#include <etl/mdspan.hpp>

#include <etl/concepts.hpp>

#include "testing/testing.hpp"

template <typename Int>
constexpr auto test_strided_slice() -> bool
{
    auto slice = etl::strided_slice {Int(1), Int(2), Int(3)};
    assert(etl::same_as<typename decltype(slice)::offset_type, Int>);
    assert(etl::same_as<typename decltype(slice)::extent_type, Int>);
    assert(etl::same_as<typename decltype(slice)::stride_type, Int>);

    assert(slice.offset == Int(1));
    assert(slice.extent == Int(2));
    assert(slice.stride == Int(3));

    return true;
}

constexpr auto test() -> bool
{
    assert(test_strided_slice<signed char>());
    assert(test_strided_slice<signed short>());
    assert(test_strided_slice<signed int>());
    assert(test_strided_slice<signed long>());
    assert(test_strided_slice<signed long long>());

    assert(test_strided_slice<unsigned char>());
    assert(test_strided_slice<unsigned short>());
    assert(test_strided_slice<unsigned int>());
    assert(test_strided_slice<unsigned long>());
    assert(test_strided_slice<unsigned long long>());
    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
