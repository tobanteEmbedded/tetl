// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_ITERATOR_T_HPP
#define TETL_RANGES_ITERATOR_T_HPP

#include <etl/_ranges/begin.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl::ranges {

template <typename T>
using iterator_t = decltype(etl::ranges::begin(etl::declval<T&>()));

} // namespace etl::ranges

#endif // TETL_RANGES_ITERATOR_T_HPP
