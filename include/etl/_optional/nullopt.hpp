// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_OPTIONAL_NULLOPT_HPP
#define TETL_OPTIONAL_NULLOPT_HPP

namespace etl {

/// etl::nullopt_t is an empty class type used to indicate optional type
/// with uninitialized state. In particular, etl::optional has a constructor
/// with nullopt_t as a single argument, which creates an optional that does not
/// contain a value.
/// \ingroup optional
struct nullopt_t {
    explicit constexpr nullopt_t(int /*unused*/) { }
};

/// etl::nullopt is a constant of type etl::nullopt_t that is used to
/// indicate optional type with uninitialized state.
/// \relates nullopt_t
/// \ingroup optional
inline constexpr auto nullopt = etl::nullopt_t{0};

} // namespace etl

#endif // TETL_OPTIONAL_NULLOPT_HPP
