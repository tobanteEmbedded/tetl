// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstdint.hpp>
    #include <etl/functional.hpp>
    #include <etl/utility.hpp>
#endif
namespace {

template <typename T>
struct Class {
    constexpr Class(T n)
        : num(n)
    {
    }

    [[nodiscard]] constexpr auto get_num(T i) const -> T
    {
        return num + i;
    }

    T num;
};

template <typename T>
[[nodiscard]] constexpr auto get_num(T i) -> T
{
    return i;
}

} // namespace

template <typename T>
static constexpr auto test() -> bool
{
    auto lambda = [](T x) -> T { return x; };
    CHECK(etl::invoke(lambda, T(1)) == T(1));
    CHECK(etl::invoke([]() { return T(42); }) == T(42));

    CHECK(etl::invoke(get_num<T>, T(42)) == T(42));
    CHECK(etl::invoke(&Class<T>::get_num, Class<T>{0}, T(42)) == T(42));
    CHECK(etl::invoke(&Class<T>::num, Class<T>{2}) == T(2));

    auto c   = Class<T>{0};
    auto ref = etl::ref(c);
    CHECK(etl::invoke(&Class<T>::get_num, ref, T(42)) == T(42));
    CHECK(etl::invoke(&Class<T>::num, ref) == T(0));

    auto cref = etl::cref(c);
    CHECK(etl::invoke(&Class<T>::get_num, cref, T(42)) == T(42));
    CHECK(etl::invoke(&Class<T>::num, cref) == T(0));

    // Using with a free function:
    auto isSame   = [](T lhs, T rhs) { return etl::equal_to{}(lhs, rhs); };
    auto isDiffer = etl::not_fn(isSame);
    CHECK(isDiffer(T(6), T(9)));
    CHECK_FALSE(isDiffer(T(8), T(8)));
    CHECK(etl::as_const(isDiffer)(T(6), T(9)));
    CHECK_FALSE(etl::as_const(isDiffer)(T(8), T(8)));

    auto isDifferStateless = etl::not_fn<isSame>();
    CHECK(isDifferStateless(T(6), T(9)));
    CHECK_FALSE(isDifferStateless(T(8), T(8)));

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
