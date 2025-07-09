module;

#include <etl/concepts.hpp>

export module etl.concepts;

export namespace etl {

using etl::assignable_from;
using etl::common_reference_with;
using etl::common_with;
using etl::constructible_from;
using etl::convertible_to;
using etl::copy_constructible;
using etl::copyable;
using etl::default_initializable;
using etl::derived_from;
using etl::destructible;
using etl::equality_comparable;
using etl::equivalence_relation;
using etl::floating_point;
using etl::integral;
using etl::invocable;
using etl::movable;
using etl::move_constructible;
using etl::predicate;
using etl::regular;
using etl::regular_invocable;
using etl::relation;
using etl::same_as;
using etl::semiregular;
using etl::signed_integral;
using etl::strict_weak_order;
using etl::swappable;
using etl::unsigned_integral;

// Non-standard extensions
using etl::boolean_testable;
using etl::builtin_integer;
using etl::builtin_signed_integer;
using etl::builtin_unsigned_integer;
using etl::referenceable;
using etl::weakly_equality_comparable_with;

} // namespace etl
