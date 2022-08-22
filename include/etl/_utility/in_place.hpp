/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_UTILITY_IN_PLACE_HPP
#define TETL_UTILITY_IN_PLACE_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief Disambiguation tags that can be passed to the constructors of
/// `optional`, `variant`, and `any` to indicate that the contained
/// object should be constructed in-place, and (for the latter two) the type of
/// the object to be constructed.
///
/// The corresponding type/type templates `in_place_t`, `in_place_type_t`
/// and `in_place_index_t` can be used in the constructor's parameter list to
/// match the intended tag.
struct in_place_t {
    explicit in_place_t() = default;
};

inline constexpr auto in_place = in_place_t {};

} // namespace etl

#endif // TETL_UTILITY_IN_PLACE_HPP
