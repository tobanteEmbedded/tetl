// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_CONJUGATED_SCALAR_HPP
#define TETL_LINALG_CONJUGATED_SCALAR_HPP

#include <etl/_concepts/same_as.hpp>
#include <etl/_linalg/concepts.hpp>
#include <etl/_linalg/proxy_reference.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl::linalg::detail {

template <typename ReferenceValue>
concept conjugatable = requires {
    { conj_if_needed(declval<ReferenceValue>()) } -> same_as<ReferenceValue>;
};

template <typename Reference, conjugatable ReferenceValue>
struct conjugated_scalar : proxy_reference<Reference, ReferenceValue, conjugated_scalar<Reference, ReferenceValue>> {
    using value_type = decltype(conj_if_needed(ReferenceValue(declval<Reference>())));

    constexpr explicit conjugated_scalar(Reference reference)
        : base_type(reference)
    {
    }

    [[nodiscard]] static constexpr auto to_value(Reference reference)
    {
        return conj_if_needed(ReferenceValue(reference));
    }

private:
    using my_type   = conjugated_scalar<Reference, ReferenceValue>;
    using base_type = proxy_reference<Reference, ReferenceValue, my_type>;
};

} // namespace etl::linalg::detail

#endif // TETL_LINALG_CONJUGATED_SCALAR_HPP
