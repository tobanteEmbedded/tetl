// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_RANGES_ITERATOR_T_HPP
#define TETL_RANGES_ITERATOR_T_HPP

#include <etl/_ranges/begin.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl::ranges {

/// \ingroup ranges
template <typename T>
using iterator_t = decltype(etl::ranges::begin(etl::declval<T&>()));

} // namespace etl::ranges

#endif // TETL_RANGES_ITERATOR_T_HPP
