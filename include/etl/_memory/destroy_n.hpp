// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_MEMORY_DESTROY_N_HPP
#define TETL_MEMORY_DESTROY_N_HPP

#include <etl/_memory/addressof.hpp>
#include <etl/_memory/destroy_at.hpp>

namespace etl {

/// \brief Destroys the n objects in the range starting at first.
template <typename ForwardIt, typename Size>
constexpr auto destroy_n(ForwardIt first, Size n) -> ForwardIt
{
    for (; n > 0; (void)++first, --n) {
        etl::destroy_at(etl::addressof(*first));
    }
    return first;
}

} // namespace etl

#endif // TETL_MEMORY_DESTROY_N_HPP
