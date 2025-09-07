// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_RANGES_SENTINEL_T_HPP
#define TETL_RANGES_SENTINEL_T_HPP

#include <etl/_ranges/end.hpp>
#include <etl/_ranges/range.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl::ranges {

/// \ingroup ranges
template <etl::ranges::range R>
using sentinel_t = decltype(etl::ranges::end(etl::declval<R&>()));

} // namespace etl::ranges

#endif // TETL_RANGES_SENTINEL_T_HPP
