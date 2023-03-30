// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_BOOLEAN_TESTABLE_HPP
#define TETL_CONCEPTS_BOOLEAN_TESTABLE_HPP

#include "etl/_concepts/convertible_to.hpp"
#include "etl/_utility/forward.hpp"

#if defined(__cpp_concepts)
namespace etl {

namespace detail {
template <typename T>
concept boolean_testable_impl = convertible_to<T, bool>;
} // namespace detail

// clang-format off
template<typename T>
concept boolean_testable =
    detail::boolean_testable_impl<T> &&
    requires(T&& t) {
        { !etl::forward<T>(t) } -> detail::boolean_testable_impl;
    };
// clang-format on

} // namespace etl
#endif

#endif // TETL_CONCEPTS_BOOLEAN_TESTABLE_HPP
