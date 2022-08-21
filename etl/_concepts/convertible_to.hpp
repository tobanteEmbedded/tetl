/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONCEPTS_CONVERTIBLE_TO_HPP
#define TETL_CONCEPTS_CONVERTIBLE_TO_HPP

#include "etl/_type_traits/add_rvalue_reference.hpp"
#include "etl/_type_traits/is_convertible.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The concept convertible_to<From, To> specifies that an expression of
/// the same type and value category as those of declval<From>() can be
/// implicitly and explicitly converted to the type To, and the two forms of
/// conversion are equivalent.
template <typename From, typename To>
concept convertible_to = is_convertible_v<From, To> && requires(add_rvalue_reference_t<From> (&f)())
{
    static_cast<To>(f());
};

} // namespace etl
#endif

#endif // TETL_CONCEPTS_CONVERTIBLE_TO_HPP
