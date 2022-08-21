/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/experimental/meta/meta.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "testing/testing.hpp"

namespace meta = etl::experimental::meta;

template <typename T>
constexpr auto test() -> bool
{
    {
        using meta::traits::add_pointer;
        using meta::traits::is_same;
        struct S { };

        assert((is_same(meta::type_c<T>, meta::type_c<T>)));
        assert((is_same(meta::type_c<T const>, meta::type_c<T const>)));
        assert((is_same(meta::type_c<T volatile>, meta::type_c<T volatile>)));

        assert((!is_same(meta::type_c<T>, meta::type_c<S>)));
        assert((!is_same(meta::type_c<T const>, meta::type_c<S const>)));
    }

    {
        using meta::traits::add_pointer;
        using meta::traits::is_pointer;

        assert((!is_pointer(meta::type<T> {})));
        assert((is_pointer(meta::type<T*> {})));
        assert((is_pointer(add_pointer(meta::type<T> {}))));
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
