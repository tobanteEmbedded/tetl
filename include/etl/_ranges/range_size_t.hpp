// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_RANGE_SIZE_T_HPP
#define TETL_RANGES_RANGE_SIZE_T_HPP

#include <etl/_ranges/size.hpp>
#include <etl/_ranges/sized_range.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl::ranges {

/// \ingroup ranges
template <etl::ranges::sized_range R>
using range_size_t = decltype(etl::ranges::size(etl::declval<R&>()));

} // namespace etl::ranges

#endif // TETL_RANGES_RANGE_SIZE_T_HPP
