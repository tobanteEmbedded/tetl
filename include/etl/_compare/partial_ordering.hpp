// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPARE_PARTIAL_ORDERING_HPP
#define TETL_COMPARE_PARTIAL_ORDERING_HPP

#include "etl/_compare/detail.hpp"
#include "etl/_cstddef/nullptr_t.hpp"

#if defined(__cpp_impl_three_way_comparison)

namespace etl {

struct partial_ordering {
    static const partial_ordering less;
    static const partial_ordering equivalent;
    static const partial_ordering greater;
    static const partial_ordering unordered;

    friend constexpr auto operator==(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v.isOrdered_ && v.value_ == 0;
    }
    friend constexpr auto operator==(partial_ordering v, partial_ordering w) noexcept -> bool = default;
    friend constexpr auto operator<(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v.isOrdered_ && v.value_ < 0;
    }
    friend constexpr auto operator>(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v.isOrdered_ && v.value_ > 0;
    }
    friend constexpr auto operator<=(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v.isOrdered_ && v.value_ <= 0;
    }
    friend constexpr auto operator>=(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v.isOrdered_ && v.value_ >= 0;
    }
    friend constexpr auto operator<(nullptr_t, partial_ordering v) noexcept -> bool
    {
        return v.isOrdered_ && 0 < v.value_;
    }
    friend constexpr auto operator>(nullptr_t, partial_ordering v) noexcept -> bool
    {
        return v.isOrdered_ && 0 > v.value_;
    }
    friend constexpr auto operator<=(nullptr_t, partial_ordering v) noexcept -> bool
    {
        return v.isOrdered_ && 0 <= v.value_;
    }
    friend constexpr auto operator>=(nullptr_t, partial_ordering v) noexcept -> bool
    {
        return v.isOrdered_ && 0 >= v.value_;
    }
    friend constexpr auto operator<=>(partial_ordering v, nullptr_t) noexcept -> partial_ordering { return v; }
    friend constexpr auto operator<=>(nullptr_t, partial_ordering v) noexcept -> partial_ordering
    {
        return v < nullptr ? partial_ordering::greater : (v > nullptr ? partial_ordering::less : v);
    }

private:
    constexpr explicit partial_ordering(detail::order_result v) noexcept
        : value_ { static_cast<int8_t>(v) }, isOrdered_ { true }
    {
    }
    constexpr explicit partial_ordering(detail::compare_result v) noexcept
        : value_ { static_cast<int8_t>(v) }, isOrdered_ { false }
    {
    }

    int8_t value_;
    bool isOrdered_;
};

// clang-format off
inline constexpr partial_ordering partial_ordering::less{detail::order_result::less};
inline constexpr partial_ordering partial_ordering::equivalent{detail::order_result::equal};
inline constexpr partial_ordering partial_ordering::greater{detail::order_result::greater};
inline constexpr partial_ordering partial_ordering::unordered{detail::compare_result::unordered};
// clang-format on

} // namespace etl

#endif

#endif // TETL_COMPARE_PARTIAL_ORDERING_HPP
