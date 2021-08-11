// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_CHRONO_TIME_POINT_HPP
#define TETL_CHRONO_TIME_POINT_HPP

#include "etl/_concepts/requires.hpp"
#include "etl/_type_traits/is_convertible.hpp"

namespace etl::chrono {

/// \brief Class template time_point represents a point in time. It is
/// implemented as if it stores a value of type Duration indicating the time
/// interval from the start of the Clock's epoch.
/// \tparam Clock Must meet the requirements for Clock
/// \notes
/// [cppreference.com/w/cpp/named_req/Clock](https://en.cppreference.com/w/cpp/named_req/Clock)
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
    constexpr explicit time_point(duration const& d) noexcept : d_ { d } { }

    /// \brief Constructs a new time_point from one of several optional data
    /// sources. Constructs a time_point by converting t to duration. This
    /// constructor only participates in overload resolution if Duration2 is
    /// implicitly convertible to duration.
    template <typename Dur2, TETL_REQUIRES_(is_convertible_v<Dur2, duration>)>
    constexpr time_point(time_point<clock, Dur2> const& t)
        : d_ { t.time_since_epch() }
    {
    }

    /// \brief Returns a duration representing the amount of time between *this
    /// and the clock's epoch.
    [[nodiscard]] constexpr auto time_since_epoch() const noexcept -> duration
    {
        return d_;
    }

    /// \brief Modifies the time point by the given duration. Applies the offset
    /// d to pt. Effectively, d is added to the internally stored duration d_ as
    /// d_
    /// += d.
    constexpr auto operator+=(duration const& d) noexcept -> time_point&
    {
        d_ += d;
        return *this;
    }

    /// \brief Modifies the time point by the given duration. Applies the offset
    /// d to pt in negative direction. Effectively, d is subtracted from
    /// internally stored duration d_ as d_ -= d.
    constexpr auto operator-=(duration const& d) noexcept -> time_point&
    {
        d_ -= d;
        return *this;
    }

    /// \brief Modifies the point in time *this represents by one tick of the
    /// duration.
    constexpr auto operator++() noexcept -> time_point&
    {
        ++d_;
        return *this;
    }

    /// \brief Modifies the point in time *this represents by one tick of the
    /// duration.
    constexpr auto operator++(int) noexcept -> time_point
    {
        return time_point(d_++);
    }

    /// \brief Modifies the point in time *this represents by one tick of the
    /// duration.
    constexpr auto operator--() noexcept -> time_point&
    {
        --d_;
        return *this;
    }

    /// \brief Modifies the point in time *this represents by one tick of the
    /// duration.
    constexpr auto operator--(int) noexcept -> time_point
    {
        return time_point(d_--);
    }

    /// \brief Returns a time_point with the smallest possible duration,
    [[nodiscard]] static constexpr auto min() noexcept -> time_point
    {
        return time_point(duration::min());
    }

    /// \brief Returns a time_point with the largest possible duration,
    [[nodiscard]] static constexpr auto max() noexcept -> time_point
    {
        return time_point(duration::max());
    }

private:
    duration d_ {};
};

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto operator==(time_point<Clock, Dur1> const& lhs,
    time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() == rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto operator!=(time_point<Clock, Dur1> const& lhs,
    time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return !(lhs == rhs);
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto operator<(time_point<Clock, Dur1> const& lhs,
    time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() < rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto operator<=(time_point<Clock, Dur1> const& lhs,
    time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() <= rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto operator>(time_point<Clock, Dur1> const& lhs,
    time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() > rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto operator>=(time_point<Clock, Dur1> const& lhs,
    time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
    return lhs.time_since_epoch() >= rhs.time_since_epoch();
}

} // namespace etl::chrono

#endif // TETL_CHRONO_TIME_POINT_HPP