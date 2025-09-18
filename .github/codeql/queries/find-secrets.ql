/**
 * @name Heuristic: likely secret variable names
 * @description Flags local variables, attributes, and parameters with names that look like secrets (key, token, secret, password).
 * @kind problem
 * @id py/heuristic-secret-name
 */

import python
import codeql.concepts.internal.SensitiveDataHeuristics

predicate looksLikeSecretName(string name, string classification) {
  nameIndicatesSensitiveData(name, classification)
  and (
    classification = password() or
    classification = secret() or
    name.matches("%key%") or
    name.matches("%token%") or
    name.matches("%secret%")
  )
}

from LocalVariable lv, string classification
where looksLikeSecretName(lv.getName(), classification)
select lv, "Local variable '" + lv.getName() + "' looks like it may contain a secret (" + classification + ")."

from FunctionParameter p, string classification
where looksLikeSecretName(p.getName(), classification)
select p, "Function parameter '" + p.getName() + "' looks like it may contain a secret (" + classification + ")."

from Attribute a, string classification
where looksLikeSecretName(a.getName(), classification)
select a, "Attribute '" + a.getName() + "' looks like it may contain a secret (" + classification + ")."
