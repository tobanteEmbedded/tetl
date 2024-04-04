// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BIT_HPP
#define TETL_BIT_HPP

/// \defgroup bit bit
///	Bit manipulation functions
/// \ingroup numerics-library
/// \code{.cpp}
/// #include <etl/bit.hpp>
/// \endcode

#include <etl/_config/all.hpp>

#include <etl/_bit/bit_cast.hpp>
#include <etl/_bit/bit_ceil.hpp>
#include <etl/_bit/bit_floor.hpp>
#include <etl/_bit/bit_width.hpp>
#include <etl/_bit/byteswap.hpp>
#include <etl/_bit/countl_one.hpp>
#include <etl/_bit/countl_zero.hpp>
#include <etl/_bit/countr_one.hpp>
#include <etl/_bit/countr_zero.hpp>
#include <etl/_bit/endian.hpp>
#include <etl/_bit/has_single_bit.hpp>
#include <etl/_bit/popcount.hpp>
#include <etl/_bit/rotl.hpp>
#include <etl/_bit/rotr.hpp>

// Non-standard extensions
#include <etl/_bit/flip_bit.hpp>
#include <etl/_bit/reset_bit.hpp>
#include <etl/_bit/set_bit.hpp>
#include <etl/_bit/test_bit.hpp>

#endif // TETL_BIT_HPP
