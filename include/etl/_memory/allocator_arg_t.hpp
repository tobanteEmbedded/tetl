// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_MEMORY_ALLOCATOR_ARG_T_HPP
#define TETL_MEMORY_ALLOCATOR_ARG_T_HPP

namespace etl {

/// \brief allocator_arg_t is an empty class type used to disambiguate the
/// overloads of constructors and member functions of allocator-aware objects.
struct allocator_arg_t {
    explicit allocator_arg_t() = default;
};

/// \brief allocator_arg is a constant of type allocator_arg_t used to
/// disambiguate, at call site, the overloads of the constructors and member
/// functions of allocator-aware objects.
inline constexpr allocator_arg_t allocator_arg{};

} // namespace etl

#endif // TETL_MEMORY_ALLOCATOR_ARG_T_HPP
