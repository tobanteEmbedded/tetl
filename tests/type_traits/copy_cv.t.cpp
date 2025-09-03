// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/type_traits.hpp>
#endif

namespace {

struct Empty { };

template <typename T>
constexpr auto test() -> bool
{
    CHECK_SAME_TYPE(etl::copy_cv_t<int, T>, T);
    CHECK_SAME_TYPE(etl::copy_cv_t<float, T>, T);
    CHECK_SAME_TYPE(etl::copy_cv_t<Empty, T>, T);

    CHECK_SAME_TYPE(etl::copy_cv_t<int const, T>, T const);
    CHECK_SAME_TYPE(etl::copy_cv_t<float const, T>, T const);
    CHECK_SAME_TYPE(etl::copy_cv_t<Empty const, T>, T const);

    CHECK_SAME_TYPE(etl::copy_cv_t<int volatile, T>, T volatile);
    CHECK_SAME_TYPE(etl::copy_cv_t<float volatile, T>, T volatile);
    CHECK_SAME_TYPE(etl::copy_cv_t<Empty volatile, T>, T volatile);

    CHECK_SAME_TYPE(etl::copy_cv_t<int const volatile, T>, T const volatile);
    CHECK_SAME_TYPE(etl::copy_cv_t<float const volatile, T>, T const volatile);
    CHECK_SAME_TYPE(etl::copy_cv_t<Empty const volatile, T>, T const volatile);

    CHECK_SAME_TYPE(etl::copy_cv_t<Empty const, T const>, T const);
    CHECK_SAME_TYPE(etl::copy_cv_t<Empty volatile, T const>, T const volatile);
    CHECK_SAME_TYPE(etl::copy_cv_t<Empty const, T volatile>, T const volatile);

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

    CHECK(test<Empty>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
