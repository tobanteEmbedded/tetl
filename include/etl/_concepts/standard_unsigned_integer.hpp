// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_STANDARD_UNSIGNED_INTEGER_HPP
#define TETL_CONCEPTS_STANDARD_UNSIGNED_INTEGER_HPP

#include <etl/_type_traits/is_standard_unsigned_integer.hpp>

namespace etl {

template <typename T>
concept standard_unsigned_integer = is_standard_unsigned_integer_v<T>;

} // namespace etl

#endif // TETL_CONCEPTS_STANDARD_UNSIGNED_INTEGER_HPP
