/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDLIB_EXIT_HPP
#define TETL_CSTDLIB_EXIT_HPP

#if not defined(EXIT_SUCCESS)
    /// \brief Successful execution of a program.
    #define EXIT_SUCCESS 0
#endif

#if not defined(EXIT_FAILURE)
    /// \brief Unsuccessful execution of a program.
    #define EXIT_FAILURE 1
#endif

#endif // TETL_CSTDLIB_EXIT_HPP