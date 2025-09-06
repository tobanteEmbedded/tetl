// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_TYPE_IDENTITY_HPP
#define TETL_TYPE_TRAITS_TYPE_IDENTITY_HPP

namespace etl {

/// \ingroup type_traits
template <typename T>
struct type_identity {
    using type = T;
};

/// \ingroup type_traits
template <typename T>
using type_identity_t = typename type_identity<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_TYPE_IDENTITY_HPP
