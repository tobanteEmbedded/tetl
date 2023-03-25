/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_WEEKDAY_LAST_HPP
#define TETL_CHRONO_WEEKDAY_LAST_HPP

#include "etl/_chrono/weekday.hpp"

namespace etl::chrono {

struct weekday_last {
    constexpr explicit weekday_last(chrono::weekday const& wd) noexcept : wd_ { wd } { }

    [[nodiscard]] constexpr auto weekday() const noexcept -> chrono::weekday { return wd_; }
    [[nodiscard]] constexpr auto ok() const noexcept -> bool { return wd_.ok(); }

private:
    chrono::weekday wd_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_WEEKDAY_LAST_HPP
