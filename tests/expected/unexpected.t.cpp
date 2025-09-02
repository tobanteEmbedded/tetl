// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/expected.hpp>
    #include <etl/type_traits.hpp>
    #include <etl/utility.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK_SAME_TYPE(etl::unexpect_t, etl::decay_t<decltype(etl::unexpect)>);
    CHECK(etl::is_default_constructible_v<etl::unexpect_t>);

    auto unex = etl::unexpected{T(42)};
    CHECK(unex.error() == T(42));
    CHECK_SAME_TYPE(decltype(unex.error()), T&);
    CHECK_SAME_TYPE(decltype(etl::as_const(unex).error()), T const&);
    CHECK_SAME_TYPE(decltype(etl::move(unex).error()), T&&);
    CHECK_SAME_TYPE(decltype(etl::move(etl::as_const(unex)).error()), T const&&);

    auto other = etl::unexpected{T(99)};
    CHECK(other.error() == T(99));

    swap(unex, other);
    CHECK(unex.error() == T(99));
    CHECK(other.error() == T(42));

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
