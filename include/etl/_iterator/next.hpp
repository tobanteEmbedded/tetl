// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_NEXT_HPP
#define TETL_ITERATOR_NEXT_HPP

#include <etl/_iterator/advance.hpp>
#include <etl/_iterator/iterator_traits.hpp>

namespace etl {

/// Return the nth successor of iterator it.
/// \ingroup iterator
template <typename InputIt>
[[nodiscard]] constexpr auto next(InputIt it, typename iterator_traits<InputIt>::difference_type n = 1) -> InputIt
{
    etl::advance(it, n);
    return it;
}

} // namespace etl

#endif // TETL_ITERATOR_NEXT_HPP
