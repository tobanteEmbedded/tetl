// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CSTDDEF_TM_HPP
#define TETL_CSTDDEF_TM_HPP

namespace etl {

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

} // namespace etl

#endif // TETL_CSTDDEF_TM_HPP
