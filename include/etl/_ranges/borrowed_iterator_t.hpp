// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_BORROWED_ITERATOR_T_HPP
#define TETL_RANGES_BORROWED_ITERATOR_T_HPP

#include <etl/_ranges/borrowed_range.hpp>
#include <etl/_ranges/dangling.hpp>
#include <etl/_ranges/iterator_t.hpp>
#include <etl/_ranges/range.hpp>
#include <etl/_type_traits/conditional.hpp>

namespace etl::ranges {

template <etl::ranges::range R>
using borrowed_iterator_t
    = etl::conditional_t<etl::ranges::borrowed_range<R>, etl::ranges::iterator_t<R>, etl::ranges::dangling>;

} // namespace etl::ranges

#endif // TETL_RANGES_BORROWED_ITERATOR_T_HPP
