// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_RANGES_DESTROY_AT_HPP
#define TETL_MEMORY_RANGES_DESTROY_AT_HPP

#include <etl/_concepts/destructible.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_memory/destroy_at.hpp>
#include <etl/_type_traits/is_array.hpp>

namespace etl::ranges {

inline constexpr struct destroy_at_fn {
    template <etl::destructible T>
    constexpr auto operator()(T* p) const noexcept -> void
    {
        etl::destroy_at(p);
    }
} destroy_at;

} // namespace etl::ranges

#endif // TETL_MEMORY_RANGES_DESTROY_AT_HPP
