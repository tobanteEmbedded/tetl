// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_IN_PLACE_INDEX_HPP
#define TETL_UTILITY_IN_PLACE_INDEX_HPP

#include <etl/_cstddef/size_t.hpp>

namespace etl {

/// \brief Disambiguation tags that can be passed to the constructors of
/// etl::optional, etl::variant, and etl::any to indicate that the contained
/// object should be constructed in-place, and (for the latter two) the type of
/// the object to be constructed.
///
/// \details The corresponding type/type templates etl::in_place_t,
/// etl::in_place_type_t and etl::in_place_index_t can be used in the
/// constructor's parameter list to match the intended tag.
template <size_t I>
struct in_place_index_t {
    explicit in_place_index_t() = default;
};

/// \relates in_place_index_t
template <size_t I>
inline constexpr auto in_place_index = in_place_index_t<I>{};

} // namespace etl

#endif // TETL_UTILITY_IN_PLACE_INDEX_HPP
