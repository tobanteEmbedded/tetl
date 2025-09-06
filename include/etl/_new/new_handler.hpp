// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_NEW_NEW_HANDLER_HPP
#define TETL_NEW_NEW_HANDLER_HPP

namespace etl {

/// \brief etl::new_handler is the function pointer type (pointer to function
/// that takes no arguments and returns void), which is used by the functions
/// etl::set_new_handler and etl::get_new_handler
using new_handler = void (*)();

} // namespace etl

#endif // TETL_NEW_NEW_HANDLER_HPP
