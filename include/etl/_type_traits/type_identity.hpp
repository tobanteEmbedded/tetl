// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_TYPE_IDENTITY_HPP
#define TETL_TYPE_TRAITS_TYPE_IDENTITY_HPP

namespace etl {

template <typename T>
struct type_identity {
    using type = T;
};

template <typename T>
using type_identity_t = T;

} // namespace etl

#endif // TETL_TYPE_TRAITS_TYPE_IDENTITY_HPP
