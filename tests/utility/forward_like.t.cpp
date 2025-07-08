// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.utility;
#else
    #include <etl/utility.hpp>
#endif

namespace {
template <typename T>
constexpr auto test() -> bool
{
    struct Class { };

    using ConstClass = Class const;

    auto val = Class{};
    CHECK_NOEXCEPT(etl::forward_like<T>(val));

    auto const& constVal = val;
    CHECK_NOEXCEPT(etl::forward_like<T>(constVal));

    // mutable value
    CHECK_SAME_TYPE(decltype(etl::forward_like<T>(Class{})), Class&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T>(ConstClass{})), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T>(val)), Class&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T>(constVal)), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T>(etl::move(val))), Class&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T>(etl::move(constVal))), ConstClass&&);

    // const value
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const>(Class{})), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const>(ConstClass{})), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const>(val)), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const>(constVal)), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const>(etl::move(val))), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const>(etl::move(constVal))), ConstClass&&);

    // l-value mutable
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&>(Class{})), Class&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&>(ConstClass{})), ConstClass&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&>(val)), Class&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&>(constVal)), ConstClass&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&>(etl::move(val))), Class&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&>(etl::move(constVal))), ConstClass&);

    // l-value const
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&>(Class{})), ConstClass&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&>(ConstClass{})), ConstClass&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&>(val)), ConstClass&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&>(constVal)), ConstClass&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&>(etl::move(val))), ConstClass&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&>(etl::move(constVal))), ConstClass&);

    // r-value mutable
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&&>(Class{})), Class&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&&>(ConstClass{})), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&&>(val)), Class&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&&>(constVal)), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&&>(etl::move(val))), Class&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T&&>(etl::move(constVal))), ConstClass&&);

    // r-value const
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&&>(Class{})), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&&>(ConstClass{})), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&&>(val)), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&&>(constVal)), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&&>(etl::move(val))), ConstClass&&);
    CHECK_SAME_TYPE(decltype(etl::forward_like<T const&&>(etl::move(constVal))), ConstClass&&);

    {
        auto value    = T(1);
        auto&& result = etl::forward_like<Class&>(value);
        CHECK_SAME_TYPE(decltype(result), T&);
        CHECK(&result == &value);
    }

    {
        auto value    = T(1);
        auto&& result = etl::forward_like<Class const&>(value);
        CHECK_SAME_TYPE(decltype(result), T const&);
        CHECK(&result == &value);
    }

    {
        auto value    = T(1);
        auto&& result = etl::forward_like<Class&&>(value);
        CHECK_SAME_TYPE(decltype(result), T&&);
        CHECK(&result == &value);
    }

    {
        auto value    = T(1);
        auto&& result = etl::forward_like<Class const&&>(value);
        CHECK_SAME_TYPE(decltype(result), T const&&);
        CHECK(&result == &value);
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
    STATIC_CHECK(test_all());
    return 0;
}
