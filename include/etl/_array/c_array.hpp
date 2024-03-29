// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ARRAY_C_ARRAY_HPP
#define TETL_ARRAY_C_ARRAY_HPP

#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// \ingroup array
template <typename ValueType, etl::size_t Size>
using c_array = ValueType[Size];

/// \ingroup array
struct empty_c_array { };

} // namespace etl

#endif // TETL_ARRAY_C_ARRAY_HPP
