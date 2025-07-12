// SPDX-License-Identifier: BSL-1.0

#include "testing/iterator.hpp"
#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.array;
import etl.cstdint;
import etl.iterator;
#else
    #include <etl/array.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/iterator.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    auto data = etl::array{T(1), T(2), T(3)};
    CHECK(*data.rbegin() == *etl::make_reverse_iterator(data.end()));
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
