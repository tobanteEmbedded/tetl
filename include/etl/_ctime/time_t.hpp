// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CTIME_TIME_T_HPP
#define TETL_CTIME_TIME_T_HPP

#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// \brief Arithmetic type capable of representing times.
/// \details Although not defined, this is almost always an integral value
///          holding the number of seconds (not counting leap seconds)
///          since 00:00, Jan 1 1970 UTC, corresponding to POSIX time.
using time_t = etl::size_t;

} // namespace etl

#endif // TETL_CTIME_TIME_T_HPP
