// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CHRONO_LAST_SPEC_HPP
#define TETL_CHRONO_LAST_SPEC_HPP

namespace etl::chrono {

/// \brief last_spec is an empty tag type that is used in conjunction with other
/// calendar types to indicate the last thing in a sequence.
///
/// \details Depending on context, it may indicate the last day of a month (as
/// in 2018y/February/last, for last day of February 2018, i.e., 2018-02-28) or
/// the last day of the week in a month (as in 2018/February/Sunday[last], for
/// last Sunday of February 2018, i.e., 2018-02-25).
///
/// https://en.cppreference.com/w/cpp/chrono/last_spec
///
/// \ingroup chrono
struct last_spec {
    explicit last_spec() = default;
};

/// \relates last_spec
/// \ingroup chrono
inline constexpr auto last = last_spec{};

} // namespace etl::chrono

#endif // TETL_CHRONO_LAST_SPEC_HPP
