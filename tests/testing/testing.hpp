// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TEST_TESTING_TESTING_HPP
#define TETL_TEST_TESTING_TESTING_HPP

#include <etl/cassert.hpp>

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/type_traits.hpp>
#endif

#define CHECK(...)           TETL_ASSERT_IMPL((__VA_ARGS__))
#define CHECK_FALSE(...)     TETL_ASSERT_IMPL(not(__VA_ARGS__))
#define CHECK_NOEXCEPT(...)  CHECK(noexcept(__VA_ARGS__))
#define CHECK_SAME_TYPE(...) CHECK(etl::is_same_v<__VA_ARGS__>)
#define STATIC_CHECK(...)                                                                                              \
    do {                                                                                                               \
        static_assert(__VA_ARGS__);                                                                                    \
        CHECK(__VA_ARGS__);                                                                                            \
    } while (false)

#endif // TETL_TEST_TESTING_TESTING_HPP
