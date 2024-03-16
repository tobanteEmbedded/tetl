// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_NONTYPE_HPP
#define TETL_UTILITY_NONTYPE_HPP

namespace etl {

template <auto V>
struct nontype_t {
    explicit nontype_t() = default;
};

template <auto V>
inline constexpr auto nontype = etl::nontype_t<V>{};

} // namespace etl

#endif // TETL_UTILITY_NONTYPE_HPP
