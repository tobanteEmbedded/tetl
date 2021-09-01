/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/memory.hpp"

#include "etl/array.hpp"
#include "etl/cstddef.hpp"
#include "etl/cstdint.hpp"

#include "testing.hpp"

template <typename T>
auto test() -> bool
{
    // simple
    {
        using pointer_type = etl::pointer_int_pair<T*, 2>;

        auto ptrValue = T(42);
        pointer_type ptr { &ptrValue, 1U };
        assert(*ptr.get_pointer() == ptrValue);
        assert(ptr.get_int() == 1U);

        auto otherValue = T(143);
        ptr.set_pointer(&otherValue);
        ptr.set_int(2U);
        assert(*ptr.get_pointer() == otherValue);
        assert(ptr.get_int() == 2U);
    }

    // nested
    {
        using inner_type  = etl::pointer_int_pair<T*, 1, bool>;
        using outter_type = etl::pointer_int_pair<inner_type, 1, bool>;

        auto innerValue = T { 1 };
        auto inner      = inner_type { &innerValue };
        auto outter     = outter_type { inner, true };
        assert(*inner.get_pointer() == T { 1 });
        assert(inner.get_int() == false);
        assert(outter.get_int() == true);

        *inner.get_pointer() = T { 2 };
        inner.set_int(true);
        outter.set_int(false);

        assert(*inner.get_pointer() == T { 2 });
        assert(inner.get_int() == true);
        assert(outter.get_int() == false);

        auto copy = outter;
        assert(copy == outter);
        assert(copy <= outter);
        assert(copy >= outter);

        assert(!(copy != outter));
        assert(!(copy < outter));
        assert(!(copy > outter));
    }

    return true;
}

auto test_all() -> bool
{
    // assert(test<etl::int8_t>());
    // assert(test<etl::int16_t>());
    // assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    // assert(test<etl::uint8_t>());
    // assert(test<etl::uint16_t>());
    // assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    // assert(test<float>());
    assert(test<double>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    return 0;
}