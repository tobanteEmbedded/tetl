// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TUPLE_IGNORE_HPP
#define TETL_TUPLE_IGNORE_HPP

namespace etl {

/// \brief An object of unspecified type such that any value can be assigned to
/// it with no effect. Intended for use with etl::tie when unpacking a
/// etl::tuple, as a placeholder for the arguments that are not used.
inline constexpr struct ignore {
    template <typename T>
    constexpr auto operator=(T const& /*unused*/) const -> auto const&
    {
        return *this;
    }
} ignore;

} // namespace etl

#endif // TETL_TUPLE_IGNORE_HPP
