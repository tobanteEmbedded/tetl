#include "etl/expected.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("expected: unexpect_t", "[expected]")
{
  using etl::decay_t;
  using etl::is_default_constructible_v;
  using etl::is_same_v;
  using etl::unexpect;
  using etl::unexpect_t;

  STATIC_REQUIRE(is_same_v<unexpect_t, decay_t<decltype(unexpect)>>);
  STATIC_REQUIRE(is_default_constructible_v<unexpect_t>);
}