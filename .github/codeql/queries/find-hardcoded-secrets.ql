import python

/**
 * @name Hardcoded secret in Python
 * @description Flags hardcoded API keys, tokens, or passwords.
 * @kind problem
 * @problem.severity warning
 * @tags security
 */

from AssignStmt assign, Expr rhs, Name lhs
where
  lhs.getId().regexpMatch("(?i)(api[_-]?key|secret|token|password)")
  and rhs instanceof StrConst
select assign, "Hardcoded secret found: " + lhs.getId()
