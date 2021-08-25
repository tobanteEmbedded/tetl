/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
inline constexpr allocator_arg_t allocator_arg {};

} // namespace etl

#endif // TETL_MEMORY_ALLOCATOR_ARG_T_HPP