// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_IOS_TYPEDEFS_HPP
#define TETL_IOS_TYPEDEFS_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/make_signed.hpp>

namespace etl {

using streamoff  = long;
using streamsize = make_signed_t<size_t>;

} // namespace etl
#endif // TETL_IOS_TYPEDEFS_HPP
