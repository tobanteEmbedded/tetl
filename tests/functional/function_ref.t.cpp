// SPDX-License-Identifier: BSL-1.0

#include <etl/functional.hpp>

#include <etl/cstdint.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

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

    CHECK(sizeof(etl::function_ref<T(T)>) == sizeof(void*) * 2);

    auto ref = etl::function_ref<T(T)>{lambda};
    CHECK(ref(T{41}) == T{42});
    CHECK(etl::invoke(ref, T{41}) == T{42});

    ref = test_function_ref<T>;
    CHECK(ref(T{41}) == T{82});
    CHECK(etl::invoke(ref, T{41}) == T{82});

    ref = lambda2;
    CHECK(ref(T{41}) == T{41});
    CHECK(etl::invoke(ref, T{41}) == T{41});

    auto other = etl::function_ref<T(T)>{test_function_ref<T>};
    CHECK(other(T{41}) == T{82});
    CHECK(etl::invoke(other, T{41}) == T{82});

    other.swap(ref);
    CHECK(ref(T{41}) == T{82});
    CHECK(etl::invoke(ref, T{41}) == T{82});
    CHECK(other(T{41}) == T{41});
    CHECK(etl::invoke(other, T{41}) == T{41});

    swap(other, ref);
    CHECK(other(T{41}) == T{82});
    CHECK(etl::invoke(other, T{41}) == T{82});
    CHECK(ref(T{41}) == T{41});
    CHECK(etl::invoke(ref, T{41}) == T{41});

    return true;
}

constexpr auto test_all() -> bool
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
    CHECK(test_all());
    // static_assert(test_all());
    return 0;
}
