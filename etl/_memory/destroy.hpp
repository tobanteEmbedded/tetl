/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_DESTROY_HPP
#define TETL_MEMORY_DESTROY_HPP

#include "etl/_memory/addressof.hpp"
#include "etl/_memory/destroy_at.hpp"

namespace etl {

/// \brief Destroys the objects in the range [first, last).
template <typename ForwardIt>
constexpr auto destroy(ForwardIt first, ForwardIt last) -> void
{
    for (; first != last; ++first) { etl::destroy_at(etl::addressof(*first)); }
}

} // namespace etl

#endif // TETL_MEMORY_DESTROY_HPP