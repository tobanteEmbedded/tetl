// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TEST_TESTING_TESTING_HPP
#define TETL_TEST_TESTING_TESTING_HPP

#undef NDEBUG
#include <etl/cassert.hpp>
#include <etl/type_traits.hpp>

#define ASSERT(...)           assert((__VA_ARGS__))
#define ASSERT_NOEXCEPT(...)  static_assert(noexcept(__VA_ARGS__), "Operation must be noexcept")
#define ASSERT_SAME_TYPE(...) static_assert(etl::is_same_v<__VA_ARGS__>, "Type mismatch")

#endif // TETL_TEST_TESTING_TESTING_HPP
