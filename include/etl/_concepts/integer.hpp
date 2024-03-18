// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_INTEGER_HPP
#define TETL_CONCEPTS_INTEGER_HPP

#include <etl/_type_traits/is_integer.hpp>

namespace etl {

template <typename T>
concept integer = is_integer_v<T>;

} // namespace etl

#endif // TETL_CONCEPTS_INTEGER_HPP
