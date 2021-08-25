/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_NEW_NOTHROW_HPP
#define TETL_NEW_NOTHROW_HPP

namespace etl {

/// \brief etl::nothrow_t is an empty class type used to disambiguate the
/// overloads of throwing and non-throwing allocation functions.
struct nothrow_t {
    explicit nothrow_t() = default;
};

/// \brief etl::nothrow is a constant of type etl::nothrow_t used to
/// disambiguate the overloads of throwing and non-throwing allocation
/// functions.
inline constexpr auto nothrow = etl::nothrow_t {};

} // namespace etl

#endif // TETL_NEW_NOTHROW_HPP