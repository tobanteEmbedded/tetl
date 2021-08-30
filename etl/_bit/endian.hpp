/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_ENDIAN_HPP
#define TETL_BIT_ENDIAN_HPP

namespace etl {

/// \brief Indicates the endianness of all scalar types. If all scalar types are
/// little-endian, `endian::native` equals `endian::little`. If all scalar types
/// are big-endian, `endian::native` equals `endian::big`.
///
/// https://en.cppreference.com/w/cpp/types/endian
/// \module Numeric
enum struct endian {
#if defined(DOXYGEN)
    little = implementation defined,
    big    = implementation defined,
    native = implementation defined,
#else
    #ifdef _WIN32
    little = 0,
    big    = 1,
    native = little
    #else
    little = __ORDER_LITTLE_ENDIAN__,
    big    = __ORDER_BIG_ENDIAN__,
    native = __BYTE_ORDER__
    #endif
#endif
};

} // namespace etl

#endif // TETL_BIT_ENDIAN_HPP