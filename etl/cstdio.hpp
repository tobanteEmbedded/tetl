/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDIO_HPP
#define TETL_CSTDIO_HPP

#include "etl/_config/all.hpp"

#if __has_include(<stdio.h>)
#include <stdio.h>
#else

#include "etl/_cstddef/max_align_t.hpp"
#include "etl/_cstddef/null.hpp"
#include "etl/_cstddef/nullptr_t.hpp"
#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_cstddef/size_t.hpp"

#endif // has_include <stdio.h>

#endif // TETL_CSTDIO_HPP