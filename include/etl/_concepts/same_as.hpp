// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_SAME_AS_HPP
#define TETL_CONCEPTS_SAME_AS_HPP

#include <etl/_type_traits/is_same.hpp>

namespace etl {

namespace detail {
template <typename T, typename U>
concept same_helper = etl::is_same_v<T, U>;
}

/// \brief The concept same_as<T, U> is satisfied if and only if T and U denote
/// the same type. same_as<T, U> subsumes same_as<U, T> and vice versa.
template <typename T, typename U>
concept same_as = detail::same_helper<T, U> and detail::same_helper<U, T>;

} // namespace etl

#endif // TETL_CONCEPTS_SAME_AS_HPP
