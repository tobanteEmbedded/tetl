// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CTIME_TIMESPEC_HPP
#define TETL_CTIME_TIMESPEC_HPP

#include <etl/_ctime/time_t.hpp>

namespace etl {

struct timespec {
    etl::time_t tv_sec;
    long tv_nsec;
};

} // namespace etl

#endif // TETL_CTIME_TIMESPEC_HPP
