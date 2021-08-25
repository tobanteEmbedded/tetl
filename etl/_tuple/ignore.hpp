

/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TUPLE_IGNORE_HPP
#define TETL_TUPLE_IGNORE_HPP

namespace etl {

namespace detail {
struct ignore_t {
    template <typename T>
    constexpr auto operator=(T const& /*unused*/) const -> ignore_t const&
    {
        return *this;
    }
};
} // namespace detail

/// \brief An object of unspecified type such that any value can be assigned to
/// it with no effect. Intended for use with etl::tie when unpacking a
/// etl::tuple, as a placeholder for the arguments that are not used.
inline constexpr auto ignore = detail::ignore_t {};

} // namespace etl

#endif // TETL_TUPLE_IGNORE_HPP