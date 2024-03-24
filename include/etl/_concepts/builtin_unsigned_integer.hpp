// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_BUILTIN_UNSIGNED_INTEGER_HPP
#define TETL_CONCEPTS_BUILTIN_UNSIGNED_INTEGER_HPP

#include <etl/_type_traits/is_builtin_unsigned_integer.hpp>

namespace etl {

template <typename T>
concept builtin_unsigned_integer = is_builtin_unsigned_integer_v<T>;

} // namespace etl

#endif // TETL_CONCEPTS_BUILTIN_UNSIGNED_INTEGER_HPP
