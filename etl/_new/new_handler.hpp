/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_NEW_NEW_HANDLER_HPP
#define TETL_NEW_NEW_HANDLER_HPP

namespace etl {

/// \brief etl::new_handler is the function pointer type (pointer to function
/// that takes no arguments and returns void), which is used by the functions
/// etl::set_new_handler and etl::get_new_handler
using new_handler = void (*)();

} // namespace etl

#endif // TETL_NEW_NEW_HANDLER_HPP