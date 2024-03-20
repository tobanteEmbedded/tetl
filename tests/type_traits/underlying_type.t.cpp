// SPDX-License-Identifier: BSL-1.0

#include <etl/type_traits.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"
#include "testing/types.hpp"

template <typename T>
constexpr auto test() -> bool
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

constexpr auto test_all() -> bool
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
