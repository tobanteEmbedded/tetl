// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_DESTRUCTIBLE_HPP
#define TETL_CONCEPTS_DESTRUCTIBLE_HPP

#include "etl/_type_traits/is_nothrow_destructible.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The concept destructible specifies the concept of all types whose
/// instances can safely be destroyed at the end of their lifetime (including
/// reference types).
template <typename T>
concept destructible = is_nothrow_destructible_v<T>;

} // namespace etl
#endif

#endif // TETL_CONCEPTS_DESTRUCTIBLE_HPP
