// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.functional;
#else
    #include <etl/functional.hpp>
#endif

namespace {

template <typename T>
auto times2(T x) -> T
{
    return static_cast<T>(x * 2);
}

template <typename T>
constexpr auto test() -> bool
{
    CHECK(sizeof(etl::function_ref<T(T)>) == sizeof(void*) * 2);

    {
        auto const plus1 = [](T x) { return static_cast<T>(x + T(1)); };
        auto const func  = etl::function_ref<T(T)>{plus1};
        CHECK(func(T(41)) == T(42));
        CHECK(etl::invoke(func, T(41)) == T(42));
    }

    {
        etl::function_ref func = times2<T>;
        CHECK(func(T(41)) == T(82));
        CHECK(etl::invoke(func, T(41)) == T(82));
    }

    return true;
}

constexpr auto test_all() -> bool
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

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

} // namespace

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
