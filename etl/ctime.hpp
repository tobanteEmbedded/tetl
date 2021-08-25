/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CTIME_HPP
#define TETL_CTIME_HPP

#include "etl/_config/all.hpp"

#include "etl/_cstddef/null.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_cstddef/tm.hpp"

namespace etl {

using clock_t = etl::size_t;
using time_t  = etl::size_t;

struct timespec {
    etl::time_t tv_sec;
    long tv_nsec;
};

} // namespace etl

#endif // TETL_CTIME_HPP