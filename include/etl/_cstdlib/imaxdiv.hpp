// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDLIB_IMAXDIV_HPP
#define TETL_CSTDLIB_IMAXDIV_HPP

#include <etl/_cstdint/intmax_t.hpp>

namespace etl {

/// \brief Return type for div, ldiv, lldiv & imaxdiv.
struct imaxdiv_t {
    intmax_t quot;
    intmax_t rem;
};

} // namespace etl

#endif // TETL_CSTDLIB_IMAXDIV_HPP
