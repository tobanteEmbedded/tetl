/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cassert.hpp"

#include <stdio.h>
#include <stdlib.h>

namespace etl {
auto tetl_assert_handler(etl::assert_msg const& msg) -> void
{
    ::printf("EXCEPTION: %s:%d\n", msg.file, msg.line);
    ::exit(1); // NOLINT
}
} // namespace etl
