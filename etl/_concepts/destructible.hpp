/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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