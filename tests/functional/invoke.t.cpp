/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/functional.hpp"

#include "etl/cstdint.hpp"

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
    assert(etl::invoke(&Class<T>::get_num, Class<T> { 0 }, T(42)) == T(42));
    assert(etl::invoke(&Class<T>::num, Class<T> { 2 }) == T(2));

    auto c   = Class<T> { 0 };
    auto ref = etl::ref(c);
    assert(etl::invoke(&Class<T>::get_num, ref, T(42)) == T(42));
    assert(etl::invoke(&Class<T>::num, ref) == T(0));

    auto cref = etl::cref(c);
    assert(etl::invoke(&Class<T>::get_num, cref, T(42)) == T(42));
    assert(etl::invoke(&Class<T>::num, cref) == T(0));
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
