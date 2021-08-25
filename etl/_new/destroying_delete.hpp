/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_NEW_DESTROY_DELETE_HPP
#define TETL_NEW_DESTROY_DELETE_HPP

namespace etl {

/// \brief Tag type used to identify the destroying delete form of operator
/// delete.
struct destroying_delete_t {
    explicit destroying_delete_t() = default;
};

/// \brief Tag type used to identify the destroying delete form of operator
/// delete.
inline constexpr auto destroying_delete = destroying_delete_t {};

} // namespace etl

#endif // TETL_NEW_DESTROY_DELETE_HPP