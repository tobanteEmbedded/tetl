/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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