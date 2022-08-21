/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_DESTROY_N_HPP
#define TETL_MEMORY_DESTROY_N_HPP

#include "etl/_memory/addressof.hpp"
#include "etl/_memory/destroy_at.hpp"

namespace etl {

/// \brief Destroys the n objects in the range starting at first.
template <typename ForwardIt, typename Size>
constexpr auto destroy_n(ForwardIt first, Size n) -> ForwardIt
{
    for (; n > 0; (void)++first, --n) { etl::destroy_at(etl::addressof(*first)); }
    return first;
}

} // namespace etl

#endif // TETL_MEMORY_DESTROY_N_HPP
