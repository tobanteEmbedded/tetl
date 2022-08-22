/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDDEF_NULL_HPP
#define TETL_CSTDDEF_NULL_HPP

#if not defined(NULL)
    /// \brief The macro NULL is an implementation-defined null pointer
    /// constant, which may be a prvalue of type nullptr_t.
    #define NULL nullptr
#endif

#endif // TETL_CSTDDEF_NULL_HPP
