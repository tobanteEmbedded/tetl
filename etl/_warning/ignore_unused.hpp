/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_WARNING_IGNORE_UNUSED_HPP
#define TETL_WARNING_IGNORE_UNUSED_HPP

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

#endif // TETL_WARNING_IGNORE_UNUSED_HPP