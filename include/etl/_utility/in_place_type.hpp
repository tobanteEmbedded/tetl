// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_IN_PLACE_TYPE_HPP
#define TETL_UTILITY_IN_PLACE_TYPE_HPP

#include "etl/_cstddef/size_t.hpp"

namespace etl {

/// \brief Disambiguation tags that can be passed to the constructors of
/// etl::optional, etl::variant, and etl::any to indicate that the contained
/// object should be constructed in-place, and (for the latter two) the type of
/// the object to be constructed.
///
/// \details The corresponding type/type templates etl::in_place_t,
/// etl::in_place_type_t and etl::in_place_index_t can be used in the
/// constructor's parameter list to match the intended tag.
template <typename T>
struct in_place_type_t {
    explicit in_place_type_t() = default;
};

template <typename T>
inline constexpr auto in_place_type = in_place_type_t<T>{};

} // namespace etl

#endif // TETL_UTILITY_IN_PLACE_TYPE_HPP
