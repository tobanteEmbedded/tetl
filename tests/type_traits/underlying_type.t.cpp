// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"
#include "testing/types.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/type_traits.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    enum E : T {
        foobar
    };
    enum struct SE : T {
        a,
        b,
        c
    };

    CHECK_TRAIT_TYPE_CV(underlying_type, E, T);
    CHECK_TRAIT_TYPE_CV(underlying_type, SE, T);

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<char>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
