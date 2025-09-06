// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_UTILITY_PIECEWISE_CONSTRUCT_HPP
#define TETL_UTILITY_PIECEWISE_CONSTRUCT_HPP

#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// \brief etl::piecewise_construct_t is an empty class tag type used to
/// disambiguate between different functions that take two tuple arguments.
///
/// \details The overloads that do not use etl::piecewise_construct_t assume
/// that each tuple argument becomes the element of a pair. The overloads that
/// use etl::piecewise_construct_t assume that each tuple argument is used to
/// construct, piecewise, a new object of specified type, which will become the
/// element of the pair.
///
/// https://en.cppreference.com/w/cpp/utility/piecewise_construct_t
struct piecewise_construct_t {
    explicit piecewise_construct_t() = default;
};

/// \brief The constant etl::piecewise_construct is an instance of an empty
/// struct tag type etl::piecewise_construct_t.
inline constexpr auto piecewise_construct = piecewise_construct_t{};

} // namespace etl

#endif // TETL_UTILITY_PIECEWISE_CONSTRUCT_HPP
