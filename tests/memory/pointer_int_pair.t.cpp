// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/memory.hpp>
#endif

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)

template <typename T>
static auto test() -> bool
{
    // simple
    {
        using pointer_type = etl::pointer_int_pair<T*, 2>;

        auto ptrValue = T(42);
        pointer_type ptr{&ptrValue, 1U};
        CHECK(*ptr.get_pointer() == ptrValue);
        CHECK(ptr.get_int() == 1U);

        auto otherValue = T(143);
        ptr.set_pointer(&otherValue);
        ptr.set_int(2U);
        CHECK(*ptr.get_pointer() == otherValue);
        CHECK(ptr.get_int() == 2U);
    }

    // nested
    {
        using inner_type  = etl::pointer_int_pair<T*, 1, bool>;
        using outter_type = etl::pointer_int_pair<inner_type, 1, bool>;

        auto innerValue = T{1};
        auto inner      = inner_type{&innerValue};
        auto outter     = outter_type{inner, true};
        CHECK(*inner.get_pointer() == T{1});
        CHECK(inner.get_int() == false);
        CHECK(outter.get_int() == true);

        *inner.get_pointer() = T{2};
        inner.set_int(true);
        outter.set_int(false);

        CHECK(*inner.get_pointer() == T{2});
        CHECK(inner.get_int() == true);
        CHECK(outter.get_int() == false);

        auto copy = outter;
        CHECK(copy == outter);
        CHECK(copy <= outter);
        CHECK(copy >= outter);

        CHECK_FALSE(copy != outter);
        CHECK_FALSE(copy < outter);
        CHECK_FALSE(copy > outter);
    }

    return true;
}

static auto test_all() -> bool
{
    // CHECK(test<etl::int8_t>());
    // CHECK(test<etl::int16_t>());
    // CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    // CHECK(test<etl::uint8_t>());
    // CHECK(test<etl::uint16_t>());
    // CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    // CHECK(test<float>());
    CHECK(test<double>());
    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
#else
auto main() -> int { return 0; }
#endif
