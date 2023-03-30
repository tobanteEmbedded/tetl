// SPDX-License-Identifier: BSL-1.0

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
