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

#ifndef TAETL_CHRONO_HPP
#define TAETL_CHRONO_HPP

#include "etl/ratio.hpp"
#include "etl/type_traits.hpp"

#include "etl/detail/sfinae.hpp"

// Somehow the abs macro gets included in avr-gcc builds. Not sure where it's
// coming from.
#ifdef abs
#undef abs
#endif

namespace etl::chrono
{
/// \brief The etl::chrono::duration_values type defines three common durations.
///
/// \details The zero, min, and max methods in etl::chrono::duration forward
/// their work to these methods. This type can be specialized if the
/// representation Rep requires a specific implementation to return these
/// duration objects.
template <typename Rep>
struct duration_values
{
  public:
  /// \brief Returns a zero-length representation.
  [[nodiscard]] static constexpr auto zero() -> Rep { return Rep {}; }

  /// \brief Returns the smallest possible representation.
  [[nodiscard]] static constexpr auto min() -> Rep
  {
    return etl::numeric_limits<Rep>::lowest();
  }

  /// \brief Returns the special duration value max.
  [[nodiscard]] static constexpr auto max() -> Rep
  {
    return etl::numeric_limits<Rep>::max();
  }
};

/// \brief The etl::chrono::treat_as_floating_point trait helps determine if a
/// duration can be converted to another duration with a different tick period.
///
/// \details Implicit conversions between two durations normally depends on the
/// tick period of the durations. However, implicit conversions can happen
/// regardless of tick period if
/// etl::chrono::treat_as_floating_point<Rep>::value == true.
///
/// \note etl::chrono::treat_as_floating_point may be specialized for
/// program-defined types.
/// \group treat_as_floating_point
template <typename Rep>
struct treat_as_floating_point : etl::is_floating_point<Rep>
{
};

/// \group treat_as_floating_point
template <typename Rep>
inline constexpr bool treat_as_floating_point_v
  = treat_as_floating_point<Rep>::value;

/// \brief Class template etl::chrono::duration represents a time interval.
///
/// \details It consists of a count of ticks of type Rep and a tick period,
/// where the tick period is a compile-time rational constant representing the
/// number of seconds from one tick to the next. The only data stored in a
/// duration is a tick count of type Rep. If Rep is floating point, then the
/// duration can represent fractions of ticks. Period is included as part of the
/// duration's type, and is only used when converting between different
/// durations.
template <typename Rep, typename Period = etl::ratio<1>>
class duration
{
  public:
  /// \brief Rep, an arithmetic type representing the number of ticks.
  using rep = Rep;

  /// \brief A etl::ratio representing the tick period (i.e. the number of
  /// seconds per tick).
  using period = typename Period::type;

  /// \brief Constructs a new duration from one of several optional data
  /// sources. The default constructor is defaulted.
  constexpr duration() noexcept = default;

  /// \brief Constructs a new duration from one of several optional data
  /// sources. The copy constructor is defaulted (makes a bitwise copy of the
  /// tick count).
  constexpr duration(duration const&) noexcept = default;

  /// \brief Constructs a duration with r ticks.
  ///
  /// \details  Note that this constructor only participates in overload
  /// resolution if const Rep2& (the argument type) is implicitly convertible
  /// to rep (the type of this duration's ticks) and
  /// treat_as_floating_point<rep>::value is true, or
  /// treat_as_floating_point<Rep2>::value is false.
  ///
  /// That is, a duration with an integer tick count cannot be constructed from
  /// a floating-point value, but a duration with a floating-point tick count
  /// can be constructed from an integer value
  template <
    typename Rep2,
    TAETL_REQUIRES_((is_convertible_v<Rep2, rep>)&&(
      treat_as_floating_point_v<rep> || !treat_as_floating_point_v<Rep2>))>
  constexpr explicit duration(Rep2 const& r) noexcept : rep_(r)
  {
  }

  /// \brief  Constructs a duration by converting d to an appropriate period
  /// and tick count, as if by duration_cast<duration>(d).count().
  ///
  /// \details In order to prevent truncation during conversion, this
  /// constructor only participates in overload resolution if computation of
  /// the conversion factor (by etl::ratio_divide<Period2, Period>) does not
  /// overflow and:
  ///
  /// treat_as_floating_point<rep>::value == true
  ///
  /// or both:
  ///
  /// ratio_divide<Period2, period>::den == 1, and
  /// treat_as_floating_point<Rep2>::value == false
  ///
  /// That is, either the duration uses floating-point ticks, or Period2 is
  /// exactly divisible by period
  template <typename Rep2, typename Period2,
            TAETL_REQUIRES_((treat_as_floating_point_v<rep>)
                            || (ratio_divide<Period2, period>::den == 1
                                && !treat_as_floating_point_v<Rep2>))>
  constexpr duration(duration<Rep2, Period2> const& other) noexcept
      : rep_(
        static_cast<Rep>(other.count() * ratio_divide<Period2, period>::num))
  {
  }

  /// \brief Assigns the contents of one duration to another.
  auto operator=(duration const& other) -> duration& = default;

  /// \brief Returns the number of ticks for this duration.
  [[nodiscard]] constexpr auto count() const -> rep { return rep_; }

  /// \brief Returns a zero-length duration.
  [[nodiscard]] static constexpr auto zero() noexcept -> duration
  {
    return duration(etl::chrono::duration_values<rep>::zero());
  }

  /// \brief Returns a duration with the lowest possible value.
  [[nodiscard]] static constexpr auto min() noexcept -> duration
  {
    return duration(etl::chrono::duration_values<rep>::min());
  }

  /// \brief Returns a duration with the largest possible value.
  [[nodiscard]] static constexpr auto max() noexcept -> duration
  {
    return duration(etl::chrono::duration_values<rep>::max());
  }

  /// \brief Implements unary plus and unary minus for the durations.
  [[nodiscard]] constexpr auto operator+() const -> etl::common_type_t<duration>
  {
    return etl::common_type_t<duration>(*this);
  }

  /// \brief Implements unary plus and unary minus for the durations.
  [[nodiscard]] constexpr auto operator-() const -> etl::common_type_t<duration>
  {
    return etl::common_type_t<duration>(-rep_);
  }

  /// \brief Increments or decrements the number of ticks for this duration.
  /// Equivalent to ++rep_; return *this;
  constexpr auto operator++() -> duration&
  {
    ++rep_;
    return *this;
  }

  /// \brief Increments or decrements the number of ticks for this duration.
  /// Equivalent to return duration(rep_++)
  constexpr auto operator++(int) -> duration { return duration(rep_++); }

  /// \brief Increments or decrements the number of ticks for this duration.
  /// Equivalent to --rep_; return *this;
  constexpr auto operator--() -> duration&
  {
    --rep_;
    return *this;
  }

  /// \brief Increments or decrements the number of ticks for this duration.
  /// Equivalent to return duration(rep_--);
  constexpr auto operator--(int) -> duration { return duration(rep_--); }

  /// \brief Performs compound assignments between two durations with the same
  /// period or between a duration and a tick count value.
  constexpr auto operator+=(duration const& d) noexcept -> duration&
  {
    return rep_ += d.count();
    return *this;
  }

  /// \brief Performs compound assignments between two durations with the same
  /// period or between a duration and a tick count value.
  constexpr auto operator-=(duration const& d) noexcept -> duration&
  {
    return rep_ -= d.count();
    return *this;
  }

  /// \brief Performs compound assignments between two durations with the same
  /// period or between a duration and a tick count value.
  constexpr auto operator*=(rep const& rhs) noexcept -> duration&
  {
    return rep_ *= rhs;
    return *this;
  }

  /// \brief Performs compound assignments between two durations with the same
  /// period or between a duration and a tick count value.
  constexpr auto operator/=(rep const& rhs) noexcept -> duration&
  {
    return rep_ /= rhs;
    return *this;
  }

  /// \brief Performs compound assignments between two durations with the same
  /// period or between a duration and a tick count value.
  constexpr auto operator%=(rep const& rhs) noexcept -> duration&
  {
    return rep_ %= rhs;
    return *this;
  }

  /// \brief Performs compound assignments between two durations with the same
  /// period or between a duration and a tick count value.
  constexpr auto operator%=(duration const& rhs) noexcept -> duration&
  {
    return rep_ %= rhs.count();
    return *this;
  }

  private:
  rep rep_ {};
};

/// \brief Class template time_point represents a point in time. It is
/// implemented as if it stores a value of type Duration indicating the time
/// interval from the start of the Clock's epoch.
/// \tparam Clock Must meet the requirements for Clock
/// https://en.cppreference.com/w/cpp/named_req/Clock
template <typename Clock, typename Duration = typename Clock::duration>
class time_point
{
  public:
  /// \brief Clock, the clock on which this time point is measured.
  using clock = Clock;

  /// \brief Duration, a duration type used to measure the time since epoch.
  using duration = Duration;

  /// \brief Rep, an arithmetic type representing the number of ticks of the
  /// duration.
  using rep = typename duration::rep;

  /// \brief Period, a ratio type representing the tick period of the duration.
  using period = typename duration::period;

  /// \brief Constructs a new time_point from one of several optional data
  /// sources. Default constructor, creates a time_point representing the
  /// Clock's epoch (i.e., time_since_epoch() is zero).
  constexpr time_point() noexcept = default;

  /// \brief Constructs a new time_point from one of several optional data
  /// sources. Constructs a time_point at Clock's epoch plus d.
  constexpr explicit time_point(duration const& d) noexcept : d_ {d} { }

  /// \brief Constructs a new time_point from one of several optional data
  /// sources. Constructs a time_point by converting t to duration. This
  /// constructor only participates in overload resolution if Duration2 is
  /// implicitly convertible to duration.
  template <typename Dur2, TAETL_REQUIRES_(is_convertible_v<Dur2, duration>)>
  constexpr time_point(time_point<clock, Dur2> const& t)
      : d_ {t.time_since_epch()}
  {
  }

  /// \brief Returns a duration representing the amount of time between *this
  /// and the clock's epoch.
  [[nodiscard]] constexpr auto time_since_epoch() const noexcept -> duration
  {
    return d_;
  }

  /// \brief Modifies the time point by the given duration. Applies the offset d
  /// to pt. Effectively, d is added to the internally stored duration d_ as d_
  /// += d.
  constexpr auto operator+=(duration const& d) noexcept -> time_point&
  {
    d_ += d;
    return *this;
  }

  /// \brief Modifies the time point by the given duration. Applies the offset d
  /// to pt in negative direction. Effectively, d is subtracted from internally
  /// stored duration d_ as d_ -= d.
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

template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator+(duration<Rep1, Period1> const& lhs,
                                       duration<Rep2, Period2> const& rhs)
  -> common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>
{
  using CD = common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>;
  return CD(CD(lhs).count() + CD(rhs).count());
}

template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator-(duration<Rep1, Period1> const& lhs,
                                       duration<Rep2, Period2> const& rhs)
  -> common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>
{
  using CD = common_type_t<duration<Rep1, Period1>, duration<Rep2, Period2>>;
  return CD(CD(lhs).count() - CD(rhs).count());
}

/// \brief Compares two durations. Checks if lhs and rhs are equal, i.e. the
/// number of ticks for the type common to both durations are equal.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator==(duration<Rep1, Period1> const& lhs,
                                        duration<Rep2, Period2> const& rhs)
  -> bool
{
  using common_t = typename etl::common_type<duration<Rep1, Period1>,
                                             duration<Rep2, Period2>>::type;

  return common_t(lhs).count() == common_t(rhs).count();
}

/// \brief Compares two durations. Checks if lhs and rhs are equal, i.e. the
/// number of ticks for the type common to both durations are equal.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator!=(duration<Rep1, Period1> const& lhs,
                                        duration<Rep2, Period2> const& rhs)
  -> bool
{
  return !(lhs == rhs);
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator<(duration<Rep1, Period1> const& lhs,
                                       duration<Rep2, Period2> const& rhs)
  -> bool
{
  using common_t = typename etl::common_type<duration<Rep1, Period1>,
                                             duration<Rep2, Period2>>::type;
  return common_t(lhs).count() < common_t(rhs).count();
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator<=(duration<Rep1, Period1> const& lhs,
                                        duration<Rep2, Period2> const& rhs)
  -> bool
{
  return !(rhs < lhs);
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator>(duration<Rep1, Period1> const& lhs,
                                       duration<Rep2, Period2> const& rhs)
  -> bool
{
  return rhs < lhs;
}

/// \brief Compares two durations. Compares lhs to rhs, i.e. compares the number
/// of ticks for the type common to both durations.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
[[nodiscard]] constexpr auto operator>=(duration<Rep1, Period1> const& lhs,
                                        duration<Rep2, Period2> const& rhs)
  -> bool
{
  return !(lhs < rhs);
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator==(time_point<Clock, Dur1> const& lhs,
           time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
  return lhs.time_since_epoch() == rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator!=(time_point<Clock, Dur1> const& lhs,
           time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
  return !(lhs == rhs);
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator<(time_point<Clock, Dur1> const& lhs,
          time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
  return lhs.time_since_epoch() < rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator<=(time_point<Clock, Dur1> const& lhs,
           time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
  return lhs.time_since_epoch() <= rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator>(time_point<Clock, Dur1> const& lhs,
          time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
  return lhs.time_since_epoch() > rhs.time_since_epoch();
}

/// \brief  Compares two time points. The comparison is done by comparing the
/// results time_since_epoch() for the time points.
template <typename Clock, typename Dur1, typename Dur2>
[[nodiscard]] constexpr auto
operator>=(time_point<Clock, Dur1> const& lhs,
           time_point<Clock, Dur2> const& rhs) noexcept -> bool
{
  return lhs.time_since_epoch() >= rhs.time_since_epoch();
}

/// \brief Signed integer type of at least 64 bits.
/// \group duration_typedefs
using nanoseconds = duration<long long, nano>;

/// \brief Signed integer type of at least 55 bits.
/// \group duration_typedefs
using microseconds = duration<long long, micro>;

/// \brief Signed integer type of at least 45 bits.
/// \group duration_typedefs
using milliseconds = duration<long long, milli>;

/// \brief Signed integer type of at least 35 bits.
/// \group duration_typedefs
using seconds = duration<long long>;

/// \brief Signed integer type of at least 29 bits.
/// \group duration_typedefs
using minutes = duration<int, ratio<60>>;

/// \brief Signed integer type of at least 23 bits.
/// \group duration_typedefs
using hours = duration<int, ratio<3600>>;

/// \brief Signed integer type of at least 25 bits.
/// \group duration_typedefs
using days = duration<int, ratio<86400>>;

/// \brief Signed integer type of at least 22 bits.
/// \group duration_typedefs
using weeks = duration<int, ratio<604800>>;

/// \brief Signed integer type of at least 17 bits.
/// \group duration_typedefs
using years = duration<int, ratio<2629746>>;

/// \brief Signed integer type of at least 20 bits.
/// \group duration_typedefs
using months = duration<int, ratio<31556952>>;

namespace detail
{
template <typename T>
struct is_duration : ::etl::false_type
{
};

template <typename Rep, typename Period>
struct is_duration<::etl::chrono::duration<Rep, Period>> : ::etl::true_type
{
};

template <typename ToDuration, typename CF, typename CR, bool NumIsOne = false,
          bool DenIsOne = false>
struct duration_cast_impl
{
  template <typename Rep, typename Period>
  [[nodiscard]] static constexpr auto
  cast(duration<Rep, Period> const& duration) noexcept(
    is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>)
    -> ToDuration
  {
    using to_rep = typename ToDuration::rep;
    return ToDuration(static_cast<to_rep>(static_cast<CR>(duration.count())
                                          * static_cast<CR>(CF::num)
                                          / static_cast<CR>(CF::den)));
  }
};

template <typename ToDuration, typename CF, typename CR>
struct duration_cast_impl<ToDuration, CF, CR, true, false>
{
  template <typename Rep, typename Period>
  [[nodiscard]] static constexpr auto
  cast(duration<Rep, Period> const& duration) noexcept(
    is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>)
    -> ToDuration
  {
    using to_rep = typename ToDuration::rep;
    return ToDuration(static_cast<to_rep>(static_cast<CR>(duration.count())
                                          / static_cast<CR>(CF::den)));
  }
};

template <typename ToDuration, typename CF, typename CR>
struct duration_cast_impl<ToDuration, CF, CR, false, true>
{
  template <typename Rep, typename Period>
  [[nodiscard]] static constexpr auto
  cast(duration<Rep, Period> const& duration) noexcept(
    is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>)
    -> ToDuration
  {
    using to_rep = typename ToDuration::rep;
    return ToDuration(static_cast<to_rep>(static_cast<CR>(duration.count())
                                          * static_cast<CR>(CF::num)));
  }
};

template <typename ToDuration, typename CF, typename CR>
struct duration_cast_impl<ToDuration, CF, CR, true, true>
{
  template <typename Rep, typename Period>
  [[nodiscard]] static constexpr auto
  cast(duration<Rep, Period> const& duration) noexcept(
    is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDuration::rep>)
    -> ToDuration
  {
    using to_rep = typename ToDuration::rep;
    return ToDuration(static_cast<to_rep>(duration.count()));
  }
};

}  // namespace detail

/// \brief Converts a duration to a duration of different type ToDur.
template <typename ToDur, typename Rep, typename Period,
          TAETL_REQUIRES_(detail::is_duration<ToDur>::value)>
[[nodiscard]] constexpr auto
duration_cast(duration<Rep, Period> const& duration) noexcept(
  is_arithmetic_v<Rep>&& is_arithmetic_v<typename ToDur::rep>) -> ToDur
{
  using detail::duration_cast_impl;
  using cf   = ratio_divide<Period, typename ToDur::period>;
  using cr   = common_type_t<typename ToDur::rep, Rep, intmax_t>;
  using impl = duration_cast_impl<ToDur, cf, cr, cf::num == 1, cf::den == 1>;
  return impl::cast(duration);
}

/// \brief Returns the greatest duration t representable in ToDuration that is
/// less or equal to d. The function does not participate in the overload
/// resolution unless ToDuration is an instance of etl::chrono::duration.
template <typename To, typename Rep, typename Period,
          TAETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto floor(duration<Rep, Period> const& d) noexcept(
  is_arithmetic_v<Rep>&& is_arithmetic_v<typename To::rep>) -> To
{
  auto const t {duration_cast<To>(d)};
  if (t > d) { return To {t.count() - static_cast<typename To::rep>(1)}; }
  return t;
}

template <typename To, typename Rep, typename Period,
          TAETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto ceil(duration<Rep, Period> const& d) noexcept(
  is_arithmetic_v<Rep>&& is_arithmetic_v<typename To::rep>) -> To
{
  auto const t {duration_cast<To>(d)};
  if (t < d) { return To {t.count() + static_cast<typename To::rep>(1)}; }
  return t;
}

template <typename To, typename Rep, typename Period,
          TAETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto round(duration<Rep, Period> const& dur) noexcept(
  is_arithmetic_v<Rep>&& is_arithmetic_v<typename To::rep>) -> To
{
  auto const low      = floor<To>(dur);
  auto const high     = low + To {1};
  auto const lowDiff  = dur - low;
  auto const highDiff = high - dur;
  if (lowDiff < highDiff) { return low; }
  if (lowDiff > highDiff) { return high; }
  return low.count() & 1 ? high : low;
}

/// \brief Returns the absolute value of the duration d. Specifically, if d >=
/// d.zero(), return d, otherwise return -d. The function does not participate
/// in the overload resolution unless etl::numeric_limits<Rep>::is_signed is
/// true.
template <typename Rep, typename Period,
          TAETL_REQUIRES_(numeric_limits<Rep>::is_signed)>
constexpr auto abs(duration<Rep, Period> d) noexcept(is_arithmetic_v<Rep>)
  -> duration<Rep, Period>
{
  return d < duration<Rep, Period>::zero() ? duration<Rep, Period>::zero() - d
                                           : d;
}

template <typename ToDuration, typename Clock, typename Duration,
          TAETL_REQUIRES_(detail::is_duration<ToDuration>::value)>
[[nodiscard]] constexpr auto
time_point_cast(time_point<Clock, Duration> const& tp) -> ToDuration
{
  using time_point_t = time_point<Clock, ToDuration>;
  return time_point_t(duration_cast<ToDuration>(tp.time_since_epoch()));
}

template <typename To, typename Clock, typename Duration,
          TAETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto floor(time_point<Clock, Duration> const& tp)
  -> time_point<Clock, To>
{
  return time_point<Clock, To> {floor<To>(tp.time_since_epoch())};
}

template <typename To, typename Clock, typename Duration,
          TAETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto ceil(time_point<Clock, Duration> const& tp)
  -> time_point<Clock, To>
{
  return time_point<Clock, To> {ceil<To>(tp.time_since_epoch())};
}

template <typename To, typename Clock, typename Duration,
          TAETL_REQUIRES_(detail::is_duration<To>::value)>
[[nodiscard]] constexpr auto round(time_point<Clock, Duration> const& tp)
  -> time_point<Clock, To>
{
  return time_point<Clock, To> {round<To>(tp.time_since_epoch())};
}

}  // namespace etl::chrono

namespace etl
{
/// \brief Exposes the type named type, which is the common type of two
/// etl::chrono::durations, whose period is the greatest common divisor of
/// Period1 and Period2.
///
/// \details The period of the resulting duration can be computed by forming a
/// ratio of the greatest common divisor of Period1::num and Period2::num and
/// the least common multiple of Period1::den and Period2::den.
template <typename Rep1, typename Period1, typename Rep2, typename Period2>
struct common_type<chrono::duration<Rep1, Period1>,
                   chrono::duration<Rep2, Period2>>
{
  private:
  static constexpr auto num = gcd(Period1::num, Period2::num);
  static constexpr auto den = lcm(Period1::den, Period2::den);

  public:
  using type = chrono::duration<common_type_t<Rep1, Rep2>, ratio<num, den>>;
};

/// \brief Exposes the type named type, which is the common type of two
/// chrono::time_points.
template <typename Clock, typename Duration1, typename Duration2>
struct common_type<chrono::time_point<Clock, Duration1>,
                   chrono::time_point<Clock, Duration2>>
{
  using type = chrono::time_point<Clock, common_type_t<Duration1, Duration2>>;
};

inline namespace literals
{
inline namespace chrono_literals
{
/// \brief Forms a etl::chrono::duration literal representing hours. Integer
/// literal, returns exactly etl::chrono::hours(hrs).
constexpr auto operator""_h(unsigned long long h) -> etl::chrono::hours
{
  return etl::chrono::hours(static_cast<etl::chrono::hours::rep>(h));
}

/// \brief Forms a etl::chrono::duration literal representing hours.
/// Floating-point literal, returns a floating-point duration equivalent to
/// etl::chrono::hours.
constexpr auto operator""_h(long double h)
  -> etl::chrono::duration<long double, ratio<3600, 1>>
{
  return etl::chrono::duration<long double, etl::ratio<3600, 1>>(h);
}

/// \brief Forms a etl::chrono::duration literal representing minutes. Integer
/// literal, returns exactly etl::chrono::minutes(mins).
constexpr auto operator""_min(unsigned long long m) -> etl::chrono::minutes
{
  return etl::chrono::minutes(static_cast<etl::chrono::minutes::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing minutes.
/// Floating-point literal, returns a floating-point duration equivalent to
/// etl::chrono::minutes.
constexpr auto operator""_min(long double m)
  -> etl::chrono::duration<long double, etl::ratio<60, 1>>
{
  return etl::chrono::duration<long double, ratio<60, 1>>(m);
}

/// \brief Forms a etl::chrono::duration literal representing seconds. Integer
/// literal, returns exactly etl::chrono::seconds(mins).
constexpr auto operator""_s(unsigned long long m) -> etl::chrono::seconds
{
  return etl::chrono::seconds(static_cast<etl::chrono::seconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing seconds.
/// Floating-point literal, returns a floating-point duration equivalent to
/// etl::chrono::seconds.
constexpr auto operator""_s(long double m) -> etl::chrono::duration<long double>
{
  return etl::chrono::duration<long double>(m);
}

/// \brief Forms a etl::chrono::duration literal representing milliseconds.
/// Integer literal, returns exactly etl::chrono::milliseconds(mins).
constexpr auto operator""_ms(unsigned long long m) -> etl::chrono::milliseconds
{
  return etl::chrono::milliseconds(
    static_cast<etl::chrono::milliseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing milliseconds.
/// Floating-point literal, returns a floating-point duration equivalent to
/// etl::chrono::milliseconds.
constexpr auto operator""_ms(long double m)
  -> etl::chrono::duration<long double, etl::milli>
{
  return etl::chrono::duration<long double, etl::milli>(m);
}

/// \brief Forms a etl::chrono::duration literal representing microseconds.
/// Integer literal, returns exactly etl::chrono::microseconds(mins).
constexpr auto operator""_us(unsigned long long m) -> etl::chrono::microseconds
{
  return etl::chrono::microseconds(
    static_cast<etl::chrono::microseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing microseconds.
/// Floating-point literal, returns a floating-point duration equivalent to
/// etl::chrono::microseconds.
constexpr auto operator""_us(long double m)
  -> etl::chrono::duration<long double, etl::micro>
{
  return etl::chrono::duration<long double, etl::micro>(m);
}

/// \brief Forms a etl::chrono::duration literal representing nanoseconds.
/// Integer literal, returns exactly etl::chrono::nanoseconds(mins).
constexpr auto operator""_ns(unsigned long long m) -> etl::chrono::nanoseconds
{
  return etl::chrono::nanoseconds(
    static_cast<etl::chrono::nanoseconds::rep>(m));
}

/// \brief Forms a etl::chrono::duration literal representing nanoseconds.
/// Floating-point literal, returns a floating-point duration equivalent to
/// etl::chrono::nanoseconds.
constexpr auto operator""_ns(long double m)
  -> etl::chrono::duration<long double, etl::nano>
{
  return etl::chrono::duration<long double, etl::nano>(m);
}

}  // namespace chrono_literals
}  // namespace literals
namespace chrono
{
using namespace ::etl::literals::chrono_literals;
}
}  // namespace etl
#endif  // TAETL_CHRONO_HPP