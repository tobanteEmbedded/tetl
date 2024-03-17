// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPARE_PARTIAL_ORDERING_HPP
#define TETL_COMPARE_PARTIAL_ORDERING_HPP

#include <etl/_compare/detail.hpp>
#include <etl/_cstddef/nullptr_t.hpp>

namespace etl {

struct partial_ordering {
    static partial_ordering const less;
    static partial_ordering const equivalent;
    static partial_ordering const greater;
    static partial_ordering const unordered;

    friend constexpr auto operator==(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v._isOrdered and v._value == 0;
    }

    friend constexpr auto operator==(partial_ordering v, partial_ordering w) noexcept -> bool = default;

    friend constexpr auto operator<(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v._isOrdered and v._value < 0;
    }

    friend constexpr auto operator>(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v._isOrdered and v._value > 0;
    }

    friend constexpr auto operator<=(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v._isOrdered and v._value <= 0;
    }

    friend constexpr auto operator>=(partial_ordering v, nullptr_t) noexcept -> bool
    {
        return v._isOrdered and v._value >= 0;
    }

    friend constexpr auto operator<(nullptr_t, partial_ordering v) noexcept -> bool
    {
        return v._isOrdered and 0 < v._value;
    }

    friend constexpr auto operator>(nullptr_t, partial_ordering v) noexcept -> bool
    {
        return v._isOrdered and 0 > v._value;
    }

    friend constexpr auto operator<=(nullptr_t, partial_ordering v) noexcept -> bool
    {
        return v._isOrdered and 0 <= v._value;
    }

    friend constexpr auto operator>=(nullptr_t, partial_ordering v) noexcept -> bool
    {
        return v._isOrdered and 0 >= v._value;
    }

    friend constexpr auto operator<=>(partial_ordering v, nullptr_t) noexcept -> partial_ordering { return v; }

    friend constexpr auto operator<=>(nullptr_t, partial_ordering v) noexcept -> partial_ordering
    {
        return v < nullptr ? partial_ordering::greater : (v > nullptr ? partial_ordering::less : v);
    }

private:
    constexpr explicit partial_ordering(detail::order_result v) noexcept
        : _value{static_cast<int8_t>(v)}
        , _isOrdered{true}
    {
    }

    constexpr explicit partial_ordering(detail::compare_result v) noexcept
        : _value{static_cast<int8_t>(v)}
        , _isOrdered{false}
    {
    }

    int8_t _value;
    bool _isOrdered;
};

inline constexpr partial_ordering partial_ordering::less{detail::order_result::less};
inline constexpr partial_ordering partial_ordering::equivalent{detail::order_result::equal};
inline constexpr partial_ordering partial_ordering::greater{detail::order_result::greater};
inline constexpr partial_ordering partial_ordering::unordered{detail::compare_result::unordered};

} // namespace etl

#endif // TETL_COMPARE_PARTIAL_ORDERING_HPP
