// SPDX-License-Identifier: BSL-1.0

#include "etl/experimental/mpl/mpl.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "testing/testing.hpp"

namespace mpl = etl::experimental::mpl;

template <typename T>
constexpr auto test() -> bool
{
    {
        using etl::integral_constant;
        using mpl::int_c;
        using mpl::type_c;

        assert((int_c<0> + int_c<0> == int_c<0>));
        assert((int_c<1> + int_c<1> == int_c<2>));
        assert((int_c<1> + int_c<2> == int_c<3>));
        assert((int_c<1> + int_c<3> == int_c<4>));

        // clang-format off
        assert((type_c<decltype(int_c<1> + int_c<1>)> == type_c<integral_constant<int, 2>>));
        assert((type_c<decltype(int_c<1> + int_c<2>)> == type_c<integral_constant<int, 3>>));
        assert((type_c<decltype(int_c<1> + int_c<3>)> == type_c<integral_constant<int, 4>>));
        // clang-format on
    }

    {

        assert((mpl::type_c<int> == mpl::type_c<int>));
        assert((mpl::type_c<int const> == mpl::type_c<int const>));
        assert((mpl::type_c<int> != mpl::type_c<int const>));

        // clang-format off
        assert((etl::is_same_v<decltype(mpl::type_c<int> == mpl::type_c<int>), etl::bool_constant<true>>));
        assert((etl::is_same_v<decltype(mpl::type_c<int> != mpl::type_c<int>), etl::bool_constant<false>>));

        assert((decltype(mpl::type_id(etl::declval<int const>())) {} == mpl::type_c<int>));
        assert((decltype(mpl::type_id(etl::declval<int volatile>())) {} == mpl::type_c<int>));
        assert((decltype(mpl::type_id(etl::declval<int const volatile>())) {} == mpl::type_c<int>));
        // clang-format on
    }

    {
        constexpr auto t = mpl::make_type_tuple<int, T>();
        assert((etl::get<0>(t) == mpl::type_c<int>));
        assert((etl::get<1>(t) == mpl::type_c<T>));
    }

    {
        using mpl::size_c;
        using mpl::size_of;
        using mpl::type_c;

        assert((size_of(type_c<T>) == size_c<sizeof(T)>));
        assert((decltype(size_of(type_c<T>) == size_c<sizeof(T)>)::value));
    }
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
