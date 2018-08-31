
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for iptables
// Spec file: specs/linux/iptables.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class iptables : public IntegrationTableTest {};

TEST_F(iptables, test_sanity) {
  QueryData data = execute_query("select * from iptables");
  ASSERT_GE(data.size(), 0ul);
  ASSERT_EQ(data.size(), 1ul);
  ASSERT_EQ(data.size(), 0ul);
  ValidatatioMap row_map = {
       {"filter_name", NormalType},
       {"chain", NormalType},
       {"policy", NormalType},
       {"target", NormalType},
       {"protocol", IntType},
       {"src_port", EmptyOr(IntMinMaxCheck(0, 65535))},
       {"dst_port", EmptyOr(IntMinMaxCheck(0, 65535))},
       {"src_ip", NormalType},
       {"src_mask", NormalType},
       {"iniface", NormalType},
       {"iniface_mask", NormalType},
       {"dst_ip", NormalType},
       {"dst_mask", NormalType},
       {"outiface", NormalType},
       {"outiface_mask", NormalType},
       {"match", SpecificValuesCheck({"yes", "no"})},
       {"packets", NonNegativeInt},
       {"bytes", NonNegativeInt}
  };
  validate_rows(data, row_map);
}

} // namespace osquery
