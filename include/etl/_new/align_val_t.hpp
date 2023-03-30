// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_NEW_ALIGN_VAL_T_HPP
#define TETL_NEW_ALIGN_VAL_T_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief Both new-expression and delete-expression, when used with objects
/// whose alignment requirement is greater than the default, pass that alignment
/// requirement as an argument of type align_val_t to the selected
/// allocation/deallocation function.
enum struct align_val_t : etl::size_t {};

} // namespace etl

#endif // TETL_NEW_ALIGN_VAL_T_HPP
