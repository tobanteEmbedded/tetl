// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_CONVERTIBLE_TO_HPP
#define TETL_CONCEPTS_CONVERTIBLE_TO_HPP

#include "etl/_type_traits/add_rvalue_reference.hpp"
#include "etl/_type_traits/is_convertible.hpp"

namespace etl {

/// \brief The concept convertible_to<From, To> specifies that an expression of
/// the same type and value category as those of declval<From>() can be
/// implicitly and explicitly converted to the type To, and the two forms of
/// conversion are equivalent.
template <typename From, typename To>
concept convertible_to
    = etl::is_convertible_v<From, To> and requires(etl::add_rvalue_reference_t<From> (&f)()) { static_cast<To>(f()); };

} // namespace etl

#endif // TETL_CONCEPTS_CONVERTIBLE_TO_HPP
