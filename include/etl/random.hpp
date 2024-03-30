// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANDOM_HPP
#define TETL_RANDOM_HPP

/// \defgroup random random
/// Random number generators and distributions
/// \ingroup numerics-library
/// \code
/// #include <etl/random.hpp>
/// \endcode

#include <etl/_config/all.hpp>

#include <etl/_random/bernoulli_distribution.hpp>
#include <etl/_random/generate_canonical.hpp>
#include <etl/_random/uniform_int_distribution.hpp>
#include <etl/_random/uniform_real_distribution.hpp>

// Non-standard extensions
#include <etl/_random/xorshift.hpp>
#include <etl/_random/xoshiro128plus.hpp>
#include <etl/_random/xoshiro128plusplus.hpp>
#include <etl/_random/xoshiro128starstar.hpp>

#endif // TETL_RANDOM_HPP
