// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_BUILTIN_SIGNED_INTEGER_HPP
#define TETL_CONCEPTS_BUILTIN_SIGNED_INTEGER_HPP

#include <etl/_type_traits/is_builtin_signed_integer.hpp>

namespace etl {

/// \note Non-standard extension
/// \headerfile etl/concepts.hpp
/// \ingroup concepts
template <typename T>
concept builtin_signed_integer = is_builtin_signed_integer_v<T>;

} // namespace etl

#endif // TETL_CONCEPTS_BUILTIN_SIGNED_INTEGER_HPP
