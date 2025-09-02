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

    // same type
    CHECK(has_common_reference<T&, T&>);
    CHECK_SAME_TYPE(etl::common_reference_t<void>, void);
    CHECK_SAME_TYPE(etl::common_reference_t<T>, T);
    CHECK_SAME_TYPE(etl::common_reference_t<T&>, T&);
    CHECK_SAME_TYPE(etl::common_reference_t<T&&>, T&&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const>, T const);
    CHECK_SAME_TYPE(etl::common_reference_t<T const&>, T const&);
    CHECK_SAME_TYPE(etl::common_reference_t<T const&&>, T const&&);

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
