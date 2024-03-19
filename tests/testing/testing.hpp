// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TEST_TESTING_TESTING_HPP
#define TETL_TEST_TESTING_TESTING_HPP

#undef NDEBUG
#include <etl/cassert.hpp>
#include <etl/type_traits.hpp>

#define CHECK(...)           assert((__VA_ARGS__))
#define CHECK_NOEXCEPT(...)  CHECK(noexcept(__VA_ARGS__))
#define CHECK_SAME_TYPE(...) CHECK(etl::is_same_v<__VA_ARGS__>)

#endif // TETL_TEST_TESTING_TESTING_HPP
