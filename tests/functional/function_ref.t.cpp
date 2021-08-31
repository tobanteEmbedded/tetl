/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/functional.hpp"

#include "etl/cstdint.hpp"
#include "etl/type_traits.hpp"

#include "helper.hpp"

namespace {

template <typename T>
auto test_function_ref(T x) -> T
{
    return static_cast<T>(x * 2);
}

} // namespace

template <typename T>
constexpr auto test() -> bool
{
    auto lambda  = [](T x) { return static_cast<T>(x + T(1)); };
    auto lambda2 = [](T x) { return static_cast<T>(x + T(0)); };

    assert((sizeof(etl::function_ref<T(T)>) == sizeof(void*) * 2));

    auto ref = etl::function_ref<T(T)> { lambda };
    assert((ref(T { 41 }) == T { 42 }));
    assert((etl::invoke(ref, T { 41 }) == T { 42 }));

    ref = test_function_ref<T>;
    assert((ref(T { 41 }) == T { 82 }));
    assert((etl::invoke(ref, T { 41 }) == T { 82 }));

    ref = lambda2;
    assert((ref(T { 41 }) == T { 41 }));
    assert((etl::invoke(ref, T { 41 }) == T { 41 }));

    auto other = etl::function_ref<T(T)> { test_function_ref<T> };
    assert((other(T { 41 }) == T { 82 }));
    assert((etl::invoke(other, T { 41 }) == T { 82 }));

    other.swap(ref);
    assert((ref(T { 41 }) == T { 82 }));
    assert((etl::invoke(ref, T { 41 }) == T { 82 }));
    assert((other(T { 41 }) == T { 41 }));
    assert((etl::invoke(other, T { 41 }) == T { 41 }));

    swap(other, ref);
    assert((other(T { 41 }) == T { 82 }));
    assert((etl::invoke(other, T { 41 }) == T { 82 }));
    assert((ref(T { 41 }) == T { 41 }));
    assert((etl::invoke(ref, T { 41 }) == T { 41 }));

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
    // static_assert(test_all());
    return 0;
}