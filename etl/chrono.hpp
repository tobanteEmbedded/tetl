/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_CHRONO_HPP
#define TAETL_CHRONO_HPP

#include "etl/definitions.hpp"
#include "etl/ratio.hpp"

namespace etl::chrono
{
/**
 * @brief The etl::chrono::duration_values type defines three common durations.
 *
 * @details The zero, min, and max methods in etl::chrono::duration forward
 * their work to these methods. This type can be specialized if the
 * representation Rep requires a specific implementation to return these
 * duration objects.
 */
template <class Rep>
struct duration_values
{
public:
    /**
     * @brief Returns a zero-length representation.
     */
    [[nodiscard]] static constexpr auto zero() -> Rep { return Rep {}; }

    /**
     * @brief Returns the smallest possible representation.
     */
    [[nodiscard]] static constexpr auto min() -> Rep
    {
        return etl::numeric_limits<Rep>::lowest();
    }

    /**
     * @brief Returns the special duration value max.
     */
    [[nodiscard]] static constexpr auto max() -> Rep
    {
        return etl::numeric_limits<Rep>::max();
    }
};
/**
 * @brief Class template etl::chrono::duration represents a time interval.
 *
 * @details It consists of a count of ticks of type Rep and a tick period, where
 * the tick period is a compile-time rational constant representing the number
 * of seconds from one tick to the next. The only data stored in a duration is a
 * tick count of type Rep. If Rep is floating point, then the duration can
 * represent fractions of ticks. Period is included as part of the duration's
 * type, and is only used when converting between different durations.
 */
template <class Rep, class Period = etl::ratio<1>>
class duration
{
public:
    /**
     * @brief Rep, an arithmetic type representing the number of ticks.
     */
    using rep = Rep;

    /**
     * @brief A etl::ratio representing the tick period (i.e. the number of
     * seconds per tick).
     */
    using period = typename Period::type;

    /**
     * @brief Constructs a new duration from one of several optional data
     * sources. The default constructor is defaulted.
     */
    constexpr duration() = default;

    /**
     * @brief Constructs a new duration from one of several optional data
     * sources. The copy constructor is defaulted (makes a bitwise copy of the
     * tick count).
     */
    duration(const duration&) = default;

    // /**
    //  * @brief Constructs a new duration from one of several optional data
    //  * sources.
    //  */
    // template <class Rep2>
    // constexpr explicit duration(const Rep2& r);

    // /**
    //  * @brief Constructs a new duration from one of several optional data
    //  * sources.
    //  */
    // template <class Rep2, class Period2>
    // constexpr duration(const duration<Rep2, Period2>& d)

    /**
     * @brief Returns the number of ticks for this duration.
     */
    [[nodiscard]] constexpr auto count() const -> rep { return data_; }

    /**
     * @brief Returns a zero-length duration.
     */
    [[nodiscard]] static constexpr auto zero() noexcept -> duration
    {
        return duration(etl::chrono::duration_values<rep>::zero());
    }

    /**
     * @brief Returns a duration with the lowest possible value.
     */
    [[nodiscard]] static constexpr auto min() noexcept -> duration
    {
        return duration(etl::chrono::duration_values<rep>::min());
    }

    /**
     * @brief Returns a duration with the largest possible value.
     */
    [[nodiscard]] static constexpr auto max() noexcept -> duration
    {
        return duration(etl::chrono::duration_values<rep>::max());
    }

private:
    rep data_ {};
};

using nanoseconds  = duration<ssize_t, etl::nano>;
using microseconds = duration<ssize_t, etl::micro>;
using milliseconds = duration<ssize_t, etl::milli>;
using seconds      = duration<ssize_t>;
using minutes      = duration<ssize_t, etl::ratio<60>>;
using hours        = duration<ssize_t, etl::ratio<3600>>;
using days         = duration<ssize_t, etl::ratio<86400>>;
using weeks        = duration<ssize_t, etl::ratio<604800>>;
using months       = duration<ssize_t, etl::ratio<2629746>>;
using years        = duration<ssize_t, etl::ratio<31556952>>;

}  // namespace etl::chrono

#endif  // TAETL_CHRONO_HPP