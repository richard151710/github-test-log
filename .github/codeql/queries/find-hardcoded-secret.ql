import python

/**
 * @name Hardcoded secret in Python
 * @description Detects hardcoded API keys, tokens, or passwords.
 * @kind problem
 * @problem.severity error
 * @tags security
 */

from AssignStmt assign, Name lhs, Expr rhs
where
  lhs.getId().regexpMatch("(?i)(api[_-]?key|secret|token|password)")
  and rhs instanceof StrConst
select assign, "Hardcoded secret found: " + lhs.getId()
