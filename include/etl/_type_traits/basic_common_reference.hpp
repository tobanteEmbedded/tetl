// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_BASIC_COMMON_REFERENCE_HPP
#define TETL_TYPE_TRAITS_BASIC_COMMON_REFERENCE_HPP

namespace etl {

/// \brief The class template basic_common_reference is a customization point
/// that allows users to influence the result of common_reference for user-defined
/// types (typically proxy references). The primary template is empty.
template <typename T, typename U, template <typename> typename TQ, template <typename> typename UQ>
struct basic_common_reference { };

} // namespace etl

#endif // TETL_TYPE_TRAITS_BASIC_COMMON_REFERENCE_HPP
