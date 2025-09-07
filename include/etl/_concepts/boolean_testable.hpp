// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CONCEPTS_BOOLEAN_TESTABLE_HPP
#define TETL_CONCEPTS_BOOLEAN_TESTABLE_HPP

#include <etl/_concepts/convertible_to.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {

namespace detail {
template <typename T>
concept boolean_testable_impl = convertible_to<T, bool>;
} // namespace detail

/// \note Non-standard extension
/// \headerfile etl/concepts.hpp
/// \ingroup concepts
template <typename T>
concept boolean_testable = etl::detail::boolean_testable_impl<T> and requires(T&& t) {
    { not etl::forward<T>(t) } -> etl::detail::boolean_testable_impl;
};

} // namespace etl

#endif // TETL_CONCEPTS_BOOLEAN_TESTABLE_HPP
