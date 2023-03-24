/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_WEEKDAY_INDEXED_HPP
#define TETL_CHRONO_WEEKDAY_INDEXED_HPP

#include "etl/_chrono/weekday.hpp"

namespace etl::chrono {

struct weekday_indexed {
    weekday_indexed() = default;
    constexpr weekday_indexed(chrono::weekday const& wd, unsigned index) noexcept
        : wd_ { wd }, index_ { static_cast<unsigned char>(index) }
    {
    }

    [[nodiscard]] constexpr auto weekday() const noexcept -> chrono::weekday { return wd_; }
    [[nodiscard]] constexpr auto index() const noexcept -> unsigned { return index_; }
    [[nodiscard]] constexpr auto ok() const noexcept -> bool
    {
        return weekday().ok() and ((index_ >= 1) and (index_ <= 5));
    }

private:
    chrono::weekday wd_;
    unsigned char index_;
};

} // namespace etl::chrono

#endif // TETL_CHRONO_WEEKDAY_INDEXED_HPP
