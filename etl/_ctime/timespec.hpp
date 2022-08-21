/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CTIME_TIMESPEC_HPP
#define TETL_CTIME_TIMESPEC_HPP

#include "etl/_ctime/time_t.hpp"

namespace etl {

struct timespec {
    etl::time_t tv_sec;
    long tv_nsec;
};

} // namespace etl

#endif // TETL_CTIME_TIMESPEC_HPP
