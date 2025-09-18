/**
 * @name Hardcoded secrets in Python (Enhanced)
 * @description Finds variables with secret-like names assigned to string literals
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @tags security
 * @id py/hardcoded-credentials-enhanced
 */

import python

from Assign assign, Name target
where
  assign.getATarget() = target and
  target.getId().regexpMatch("(?i).*(api.?key|secret|token|password).*") and
  assign.getValue() instanceof StrConst
select assign, "Potential hardcoded secret in variable: " + target.getId()
