// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_UNINITIALIZED_FILL_HPP
#define TETL_MEMORY_UNINITIALIZED_FILL_HPP

#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_memory/construct_at.hpp>

namespace etl {

template <typename ForwardIt, typename T>
auto uninitialized_fill(ForwardIt first, ForwardIt last, T const& value) -> void
{
    using ValueType = typename etl::iterator_traits<ForwardIt>::value_type;

#if defined(__cpp_exceptions)
    auto current = first;
    try {
        for (; current != last; ++current) { etl::construct_at(current, value); }
    } catch (...) {
        for (; first != current; ++first) { first->~ValueType(); }
        throw;
    }
#else
    for (auto current = first; current != last; ++current) { etl::construct_at(current, value); }
#endif
}

} // namespace etl

#endif // TETL_MEMORY_UNINITIALIZED_FILL_HPP
