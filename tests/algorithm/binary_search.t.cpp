// SPDX-License-Identifier: BSL-1.0

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

#include "testing/iterator_types.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // epmty range
    auto const e = etl::static_vector<T, 4> {};
    assert(!etl::binary_search(begin(e), end(e), T(0)));
    assert(!etl::binary_search(FwdIter(begin(e)), FwdIter(end(e)), T(0)));

    // range
    auto const data = etl::array { T(0), T(1), T(2) };
    assert(etl::binary_search(begin(data), end(data), T(0)));
    assert(etl::binary_search(begin(data), end(data), T(1)));
    assert(etl::binary_search(begin(data), end(data), T(2)));
    assert(!etl::binary_search(begin(data), end(data), T(3)));
    assert(!etl::binary_search(begin(data), end(data), T(4)));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
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
