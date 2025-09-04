// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/type_traits.hpp>
#endif

namespace {

template <typename... Ts>
concept has_common_reference = requires { typename etl::common_reference_t<Ts...>; };

template <typename T>
constexpr auto test() -> bool
{
    // empty
    CHECK_FALSE(has_common_reference<>);

    // single type
    CHECK(has_common_reference<void>);
    CHECK(has_common_reference<T>);
    CHECK(has_common_reference<T&>);
    CHECK(has_common_reference<T const&>);
    CHECK(has_common_reference<T volatile&>);
    CHECK(has_common_reference<T const volatile&>);
    CHECK(has_common_reference<T&&>);
    CHECK(has_common_reference<T const&&>);
    CHECK(has_common_reference<T volatile&&>);
    CHECK(has_common_reference<T const volatile&&>);

    CHECK_SAME_TYPE(etl::common_reference_t<void>, void);
    CHECK_SAME_TYPE(etl::common_reference_t<T>, T);
    CHECK_SAME_TYPE(etl::common_reference_t<T&>, T&);
    CHECK_SAME_TYPE(etl::common_reference_t<T&&>, T&&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const>, T const);
    CHECK_SAME_TYPE(etl::common_reference_t<T const&>, T const&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const&&>, T const&&);

    // lvalue-ref type
    CHECK_SAME_TYPE(etl::common_reference_t<T&, T&>, T&);

    CHECK_SAME_TYPE(etl::common_reference_t<T&, T const&>, T const&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const&, T&>, T const&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const&, T const&>, T const&);

    CHECK_SAME_TYPE(etl::common_reference_t<T&, T volatile&>, T volatile&);
    CHECK_SAME_TYPE(etl::common_reference_t<T volatile&, T&>, T volatile&);
    CHECK_SAME_TYPE(etl::common_reference_t<T volatile&, T volatile&>, T volatile&);

    CHECK_SAME_TYPE(etl::common_reference_t<T&, T const volatile&>, T const volatile&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const volatile&, T&>, T const volatile&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const volatile&, T&>, T const volatile&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const volatile&, T const volatile&>, T const volatile&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const volatile&, T const&>, T const volatile&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const volatile&, T volatile&>, T const volatile&);

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
