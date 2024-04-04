// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_UNINITIALIZED_COPY_HPP
#define TETL_MEMORY_UNINITIALIZED_COPY_HPP

#include <etl/_memory/addressof.hpp>
#include <etl/_memory/construct_at.hpp>
#include <etl/_memory/destroy.hpp>

namespace etl {

template <typename InputIt, typename NoThrowForwardIt>
constexpr auto uninitialized_copy(InputIt first, InputIt last, NoThrowForwardIt dest) -> NoThrowForwardIt
{
#if defined(__cpp_exceptions)
    auto current = dest;
    try {
        for (; first != last; ++first, (void)++current) {
            etl::construct_at(etl::addressof(*current), *first);
        }
        return current;
    } catch (...) {
        etl::destroy(dest, current);
        throw;
    }
#else
    auto current = dest;
    for (; first != last; ++first, (void)++current) {
        etl::construct_at(etl::addressof(*current), *first);
    }
    return current;
#endif
}

} // namespace etl

#endif // TETL_MEMORY_UNINITIALIZED_COPY_HPP
