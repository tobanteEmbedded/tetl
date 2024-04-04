// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_RANGES_CONSTRUCT_AT_HPP
#define TETL_MEMORY_RANGES_CONSTRUCT_AT_HPP

#include <etl/_memory/construct_at.hpp>
#include <etl/_utility/forward.hpp>

namespace etl::ranges {

inline constexpr struct construct_at_fn {
    template <typename T, typename... Args>
        requires requires(void* ptr, Args&&... args) { ::new (ptr) T(etl::forward<Args>(args)...); }
    constexpr auto operator()(T* p, Args&&... args) const -> T*
    {
        return etl::construct_at(p, etl::forward<Args>(args)...);
    }
} construct_at;

} // namespace etl::ranges

#endif // TETL_MEMORY_RANGES_CONSTRUCT_AT_HPP
