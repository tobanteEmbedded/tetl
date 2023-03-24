/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_MONTH_DAY_LAST_HPP
#define TETL_CHRONO_MONTH_DAY_LAST_HPP

#include "etl/_chrono/month.hpp"

namespace etl::chrono {

struct month_day_last {
    constexpr explicit month_day_last(chrono::month const& m) noexcept : m_ { m } { }

    constexpr auto month() const noexcept -> chrono::month { return m_; }
    constexpr auto ok() const noexcept -> bool { return month().ok(); }

private:
    chrono::month m_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_MONTH_DAY_LAST_HPP
