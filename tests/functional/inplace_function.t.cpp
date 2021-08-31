/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/functional.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "helper.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto func = etl::inplace_function<T(T)> {
        [](T x) { return x + T(1); },
    };

    assert(func(T { 41 }) == T { 42 });
    assert(etl::invoke(func, T { 41 }) == T { 42 });
    assert(static_cast<bool>(func));
    assert(!static_cast<bool>(etl::inplace_function<T(T)> {}));
    assert(!static_cast<bool>(etl::inplace_function<T(T)> { nullptr }));
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
    return 0;
}