/*################################################################################
  ##
  ##   Copyright (C) 2016-2020 Keith O'Hara
  ##
  ##   This file is part of the GCE-Math C++ library.
  ##
  ##   Licensed under the Apache License, Version 2.0 (the "License");
  ##   you may not use this file except in compliance with the License.
  ##   You may obtain a copy of the License at
  ##
  ##       http://www.apache.org/licenses/LICENSE-2.0
  ##
  ##   Unless required by applicable law or agreed to in writing, software
  ##   distributed under the License is distributed on an "AS IS" BASIS,
  ##   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ##   See the License for the specific language governing permissions and
  ##   limitations under the License.
  ##
  ################################################################################*/

/*
 * Gauss-Legendre quadrature: 30 points
 */

static const long double gauss_legendre_30_points[30] = { -0.05147184255531769583302521316672L,
    0.05147184255531769583302521316672L, -0.15386991360858354696379467274326L, 0.15386991360858354696379467274326L,
    -0.25463692616788984643980512981781L, 0.25463692616788984643980512981781L, -0.35270472553087811347103720708937L,
    0.35270472553087811347103720708937L, -0.44703376953808917678060990032285L, 0.44703376953808917678060990032285L,
    -0.53662414814201989926416979331107L, 0.53662414814201989926416979331107L, -0.62052618298924286114047755643119L,
    0.62052618298924286114047755643119L, -0.69785049479331579693229238802664L, 0.69785049479331579693229238802664L,
    -0.76777743210482619491797734097450L, 0.76777743210482619491797734097450L, -0.82956576238276839744289811973250L,
    0.82956576238276839744289811973250L, -0.88256053579205268154311646253023L, 0.88256053579205268154311646253023L,
    -0.92620004742927432587932427708047L, 0.92620004742927432587932427708047L, -0.96002186496830751221687102558180L,
    0.96002186496830751221687102558180L, -0.98366812327974720997003258160566L, 0.98366812327974720997003258160566L,
    -0.99689348407464954027163005091870L, 0.99689348407464954027163005091870L };

static const long double gauss_legendre_30_weights[30] = { 0.10285265289355884034128563670542L,
    0.10285265289355884034128563670542L, 0.10176238974840550459642895216855L, 0.10176238974840550459642895216855L,
    0.09959342058679526706278028210357L, 0.09959342058679526706278028210357L, 0.09636873717464425963946862635181L,
    0.09636873717464425963946862635181L, 0.09212252223778612871763270708762L, 0.09212252223778612871763270708762L,
    0.08689978720108297980238753071513L, 0.08689978720108297980238753071513L, 0.08075589522942021535469493846053L,
    0.08075589522942021535469493846053L, 0.07375597473770520626824385002219L, 0.07375597473770520626824385002219L,
    0.06597422988218049512812851511596L, 0.06597422988218049512812851511596L, 0.05749315621761906648172168940206L,
    0.05749315621761906648172168940206L, 0.04840267283059405290293814042281L, 0.04840267283059405290293814042281L,
    0.03879919256962704959680193644635L, 0.03879919256962704959680193644635L, 0.02878470788332336934971917961129L,
    0.02878470788332336934971917961129L, 0.01846646831109095914230213191205L, 0.01846646831109095914230213191205L,
    0.00796819249616660561546588347467L, 0.00796819249616660561546588347467L };
