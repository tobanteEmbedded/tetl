// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_TIME_POINT_HPP
#define TETL_CHRONO_TIME_POINT_HPP

#include "etl/_type_traits/common_type.hpp"
#include "etl/_type_traits/is_convertible.hpp"

namespace etl::chrono {

/// \brief Class template time_point represents a point in time. It is
/// implemented as if it stores a value of type Duration indicating the time
/// interval from the start of the Clock's epoch.
///
/// \tparam Clock Must meet the requirements for Clock
///
/// https://en.cppreference.com/w/cpp/named_req/Clock
template <typename Clock, typename Duration = typename Clock::duration>
struct time_point {
    /// \brief Clock, the clock on which this time point is measured.
    using clock = Clock;

    /// \brief Duration, a duration type used to measure the time since epoch.
    using duration = Duration;

    /// \brief Rep, an arithmetic type representing the number of ticks of the
    /// duration.
    using rep = typename duration::rep;

    /// \brief Period, a ratio type representing the tick period of the
    /// duration.
    using period = typename duration::period;

    /// \brief Constructs a new time_point from one of several optional data
    /// sources. Default constructor, creates a time_point representing the
    /// Clock's epoch (i.e., time_since_epoch() is zero).
    constexpr time_point() noexcept = default;

    /// \brief Constructs a new time_point from one of several optional data
    /// sources. Constructs a time_point at Clock's epoch plus d.
    constexpr explicit time_point(duration const& d) noexcept : _d{d} { }

    /// \brief Constructs a new time_point from one of several optional data
    /// sources. Constructs a time_point by converting t to duration. This
    /// constructor only participates in overload resolution if Duration2 is
    /// implicitly convertible to duration.
    template <typename Dur2>
        requires(is_convertible_v<Dur2, duration>)
    constexpr time_point(time_point<clock, Dur2> const& t) : _d{t.time_since_epch()}
    {
    }

    /// \brief Returns a duration representing the amount of time between *this
    /// and the clock's epoch.
    [[nodiscard]] constexpr auto time_since_epoch() const noexcept -> duration { return _d; }

    /// \brief Modifies the time point by the given duration. Applies the offset
    /// d to pt. Effectively, d is added to the internally stored duration d_ as
    /// d_
    /// += d.
    constexpr auto operator+=(duration const& d) noexcept -> time_point&
    {
        _d += d;
        return *this;
    }

    /// \brief Modifies the time point by the given duration. Applies the offset
    /// d to pt in negative direction. Effectively, d is subtracted from
    /// internally stored duration d_ as d_ -= d.
    constexpr auto operator-=(duration const& d) noexcept -> time_point&
    {
        _d -= d;
        return *this;
    }

    /// \brief Modifies the point in time *this represents by one tick of the
    /// duration.
    constexpr auto operator++() noexcept -> time_point&
    {
        ++_d;
        return *this;
    }

    /// \brief Modifies the point in time *this represents by one tick of the
    /// duration.
    constexpr auto operator++(int) noexcept -> time_point { return time_point(_d++); }

    /// \brief Modifies the point in time *this represents by one tick of the
    /// duration.
    constexpr auto operator--() noexcept -> time_point&
    {
        --_d;
        return *this;
    }

    /// \brief Modifies the point in time *this represents by one tick of the
    /// duration.
    constexpr auto operator--(int) noexcept -> time_point { return time_point(_d--); }

    /// \brief Returns a time_point with the smallest possible duration,
    [[nodiscard]] static constexpr auto min() noexcept -> time_point { return time_point(duration::min()); }

    /// \brief Returns a time_point with the largest possible duration,
    [[nodiscard]] static constexpr auto max() noexcept -> time_point { return time_point(duration::max()); }

private:
    duration _d{};
};

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator==(time_point<Clock, Dur1> const& lhs, time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() == rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator!=(time_point<Clock, Dur1> const& lhs, time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return !(lhs == rhs);
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator<(time_point<Clock, Dur1> const& lhs, time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() < rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator<=(time_point<Clock, Dur1> const& lhs, time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() <= rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator>(time_point<Clock, Dur1> const& lhs, time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() > rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator>=(time_point<Clock, Dur1> const& lhs, time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() >= rhs.time_since_epoch();
}

} // namespace etl::chrono

namespace etl {

/// \brief Exposes the type named type, which is the common type of two
/// chrono::time_points.
template <typename Clock, typename Duration1, typename Duration2>
struct common_type<chrono::time_point<Clock, Duration1>, chrono::time_point<Clock, Duration2>> {
    using type = chrono::time_point<Clock, common_type_t<Duration1, Duration2>>;
};

} // namespace etl

#endif // TETL_CHRONO_TIME_POINT_HPP
