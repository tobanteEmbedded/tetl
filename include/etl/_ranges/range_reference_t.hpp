// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_RANGE_REFERENCE_T_HPP
#define TETL_RANGES_RANGE_REFERENCE_T_HPP

#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_ranges/iterator_t.hpp>
#include <etl/_ranges/range.hpp>

namespace etl::ranges {

/// \ingroup ranges
template <etl::ranges::range R>
using range_reference_t = etl::iter_reference_t<etl::ranges::iterator_t<R>>;

} // namespace etl::ranges

#endif // TETL_RANGES_RANGE_REFERENCE_T_HPP
