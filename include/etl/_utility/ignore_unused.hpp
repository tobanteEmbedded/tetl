// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_IGNORE_UNUSED_HPP
#define TETL_UTILITY_IGNORE_UNUSED_HPP

namespace etl {

/// \brief Explicitly ignore arguments or variables.
/// \code
/// auto main(int argc, char** argv) -> int
/// {
///   etl::ignore_unused(argc, argv);
///   return 0;
/// }
/// \endcode
template <typename... Types>
constexpr auto ignore_unused(Types&&... /*unused*/) -> void
{
}

} // namespace etl

#endif // TETL_UTILITY_IGNORE_UNUSED_HPP
