// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_UNINITIALIZED_MOVE_HPP
#define TETL_MEMORY_UNINITIALIZED_MOVE_HPP

#include <etl/_memory/addressof.hpp>
#include <etl/_memory/construct_at.hpp>
#include <etl/_memory/destroy.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

template <typename InputIt, typename NoThrowForwardIt>
constexpr auto uninitialized_move(InputIt first, InputIt last, NoThrowForwardIt dest) -> NoThrowForwardIt
{
#if defined(__cpp_exceptions)
    auto current = dest;
    try {
        for (; first != last; ++first, (void)++current) {
            etl::construct_at(etl::addressof(*current), TETL_MOVE(*first));
        }
        return current;
    } catch (...) {
        etl::destroy(dest, current);
        throw;
    }
#else
    auto current = dest;
    for (; first != last; ++first, (void)++current) {
        etl::construct_at(etl::addressof(*current), TETL_MOVE(*first));
    }
    return current;
#endif
}

} // namespace etl

#endif // TETL_MEMORY_UNINITIALIZED_MOVE_HPP
