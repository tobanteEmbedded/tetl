// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CSTDDEF_NULL_HPP
#define TETL_CSTDDEF_NULL_HPP

#if not defined(NULL)
    /// \brief The macro NULL is an implementation-defined null pointer
    /// constant, which may be a prvalue of type nullptr_t.
    #define NULL nullptr
#endif

#endif // TETL_CSTDDEF_NULL_HPP
