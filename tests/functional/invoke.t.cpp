// SPDX-License-Identifier: BSL-1.0

#include <etl/functional.hpp>

#include <etl/cstdint.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T>
struct Class {
    constexpr Class(T n) : num(n) { }

    [[nodiscard]] constexpr auto get_num(T i) const -> T { return num + i; }

    T num;
};

template <typename T>
[[nodiscard]] constexpr auto get_num(T i) -> T
{
    return i;
}

} // namespace

template <typename T>
constexpr auto test() -> bool
{
    auto lambda = [](T x) -> T { return x; };
    assert(etl::invoke(lambda, T(1)) == T(1));
    assert(etl::invoke([]() { return T(42); }) == T(42));

    assert(etl::invoke(get_num<T>, T(42)) == T(42));
    assert(etl::invoke(&Class<T>::get_num, Class<T>{0}, T(42)) == T(42));
    assert(etl::invoke(&Class<T>::num, Class<T>{2}) == T(2));

    auto c   = Class<T>{0};
    auto ref = etl::ref(c);
    assert(etl::invoke(&Class<T>::get_num, ref, T(42)) == T(42));
    assert(etl::invoke(&Class<T>::num, ref) == T(0));

    auto cref = etl::cref(c);
    assert(etl::invoke(&Class<T>::get_num, cref, T(42)) == T(42));
    assert(etl::invoke(&Class<T>::num, cref) == T(0));

    // Using with a free function:
    auto isSame   = [](T lhs, T rhs) { return etl::equal_to{}(lhs, rhs); };
    auto isDiffer = etl::not_fn(isSame);
    assert(isDiffer(T(6), T(9)));
    assert(not isDiffer(T(8), T(8)));
    assert(etl::as_const(isDiffer)(T(6), T(9)));
    assert(not etl::as_const(isDiffer)(T(8), T(8)));

    auto isDifferStateless = etl::not_fn<isSame>();
    assert(isDifferStateless(T(6), T(9)));
    assert(not isDifferStateless(T(8), T(8)));

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
    STATIC_CHECK(test_all());
    return 0;
}
