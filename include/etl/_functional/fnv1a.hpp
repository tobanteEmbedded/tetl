// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
#ifndef TETL_FUNCTIONAL_FNV1A_HPP
#define TETL_FUNCTIONAL_FNV1A_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>
#include <etl/_cstdint/uint_t.hpp>

namespace etl {

template <typename UInt, UInt Prime, UInt Offset>
struct fnv1a {
    using result_type = UInt;

    fnv1a() = default;

    auto operator()(void const* data, etl::size_t len) noexcept -> void
    {
        auto const* p = static_cast<etl::uint8_t const*>(data);
        TETL_NO_UNROLL while (len--)
        {
            _h ^= static_cast<UInt>(*p++);
            _h *= Prime;
        }
    }

    explicit operator result_type() const noexcept
    {
        return _h;
    }

private:
    result_type _h{Offset};
};

using fnv1a32 = fnv1a<etl::uint32_t, 0x01000193, 0x811c9dc5>;
using fnv1a64 = fnv1a<etl::uint64_t, 0x00000100000001b3, 0xcbf29ce484222325>;

} // namespace etl

#endif // TETL_FUNCTIONAL_FNV1A_HPP
