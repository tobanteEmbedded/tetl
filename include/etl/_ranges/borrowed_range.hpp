// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_BORROWED_RANGE_HPP
#define TETL_RANGES_BORROWED_RANGE_HPP

#include <etl/_ranges/enable_borrowed_range.hpp>
#include <etl/_ranges/range.hpp>
#include <etl/_type_traits/is_lvalue_reference.hpp>
#include <etl/_type_traits/remove_cvref.hpp>

namespace etl::ranges {

template <typename R>
concept borrowed_range = etl::ranges::range<R>
                     and (etl::is_lvalue_reference_v<R> or etl::ranges::enable_borrowed_range<etl::remove_cvref_t<R>>);

} // namespace etl::ranges

#endif // TETL_RANGES_BORROWED_RANGE_HPP
