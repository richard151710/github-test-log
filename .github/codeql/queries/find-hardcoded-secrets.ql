/**
 * @name Hardcoded secret-like strings in Python (assignment-based)
 * @description Flags top-level and attribute assignments where RHS is a string literal and LHS name looks like a secret.
 * @kind problem
 * @id py/hardcoded-secret-assignment
 */

import python
import codeql.concepts.internal.SensitiveDataHeuristics

// secret-name heuristic
predicate secretName(string n, string classification) {
  nameIndicatesSensitiveData(n, classification) and
    (classification = password() or classification = secret() or n.matches("%key%") or n.matches("%token%") or n.matches("%secret%") or n.matches("%api%"))
}

// Look for Assign statements where RHS is a string literal
from Assign a, Expr lhs, StringLiteral rhs, string classification
where
  // RHS is a string literal
  rhs = a.getRhs() and
  // LHS is a simple name (module-level variable or attribute target)
  lhs = a.getLhs() and
  // get textual LHS name (handles simple Name and Attribute)
  (exists(Name n | n = lhs.getAnId() and secretName(n.getId(), classification))
   or
   exists(Attribute attr | attr = lhs.getAnAttribute() and secretName(attr.getAttributeName(), classification))
  )
select a, "Assignment to '" + lhs.toString() + "' has a string literal that looks like a hardcoded secret (" + classification + ")."
