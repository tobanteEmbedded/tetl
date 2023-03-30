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
        using mpl::traits::add_pointer;
        using mpl::traits::is_same;
        struct S { };

        assert((is_same(mpl::type_c<T>, mpl::type_c<T>)));
        assert((is_same(mpl::type_c<T const>, mpl::type_c<T const>)));
        assert((is_same(mpl::type_c<T volatile>, mpl::type_c<T volatile>)));

        assert((!is_same(mpl::type_c<T>, mpl::type_c<S>)));
        assert((!is_same(mpl::type_c<T const>, mpl::type_c<S const>)));
    }

    {
        using mpl::traits::add_pointer;
        using mpl::traits::is_pointer;

        assert((!is_pointer(mpl::type<T> {})));
        assert((is_pointer(mpl::type<T*> {})));
        assert((is_pointer(add_pointer(mpl::type<T> {}))));
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
