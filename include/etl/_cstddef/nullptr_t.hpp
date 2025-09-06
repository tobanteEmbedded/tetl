// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CSTDDEF_NULLPTR_T_HPP
#define TETL_CSTDDEF_NULLPTR_T_HPP

namespace etl {

/// \brief etl::nullptr_t is the type of the null pointer literal, nullptr. It
/// is a distinct type that is not itself a pointer type or a pointer to member
/// type.
///
/// https://en.cppreference.com/w/cpp/types/nullptr_t
using nullptr_t = decltype(nullptr);

} // namespace etl

#endif // TETL_CSTDDEF_NULLPTR_T_HPP
