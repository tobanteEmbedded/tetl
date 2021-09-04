/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::is_same_v;
    using etl::underlying_type;
    using etl::underlying_type_t;

    enum E : T { foobar };
    enum struct SE : T { a, b, c };

    assert((is_same_v<T, typename underlying_type<E>::type>));
    assert((is_same_v<T, underlying_type_t<SE>>));

    assert((is_same_v<T, typename underlying_type<E const>::type>));
    assert((is_same_v<T, underlying_type_t<SE const>>));

    assert((is_same_v<T, typename underlying_type<E volatile>::type>));
    assert((is_same_v<T, underlying_type_t<SE volatile>>));

    assert((is_same_v<T, typename underlying_type<E const volatile>::type>));
    assert((is_same_v<T, underlying_type_t<SE const volatile>>));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<char>());
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}