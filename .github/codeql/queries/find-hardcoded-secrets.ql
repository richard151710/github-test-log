/**
 * @name Hardcoded secret-like strings in Python
 * @description Detect assignments of string literals that look like secrets (by name or by value).
 * @kind problem
 * @id py/hardcoded-secret-like-string
 */

import python
import codeql.concepts.internal.SensitiveDataHeuristics

// Helper: name looks like secret/key/password/token
predicate looksLikeSecretName(string name, string classification) {
  nameIndicatesSensitiveData(name, classification)
  and (
    classification = password() or
    classification = secret() or
    name.matches("%key%") or
    name.matches("%token%") or
    name.matches("%secret%") or
    name.matches("%password%") or
    name.matches("%api%")
  )
}

// Helper: string literal value looks like a secret/key (length + allowed chars)
predicate looksLikeSecretValue(StringLiteral s) {
  // get the raw value (without quotes)
  exists(string v |
    v = s.getStringValue() and
    // length threshold (tunable); many keys are >= 16 chars
    size(v) >= 16 and
    // contains at least letters and digits OR looks base64-like or hex-like
    ((v.matches("%[0-9]%") and v.matches("%[A-Za-z]%"))
     or v.matches("%^[A-Fa-f0-9]{16,}$%") // hex-like (16+ hex chars)
     or v.matches("%^[A-Za-z0-9+/=]{16,}$%") // base64-like
    )
  )
}

/* 1) Local variables with hardcoded string initializer and secret-like name/value */
from LocalVariable lv, string classification
where
  lv.getAnInitializer() instanceof StringLiteral and
  (
    looksLikeSecretName(lv.getName(), classification)
    or
    exists(StringLiteral s | s = (StringLiteral) lv.getAnInitializer() and looksLikeSecretValue(s))
  )
select lv, "Local variable '" + lv.getName() + "' is assigned a string literal that looks like a secret (" + (classification = "" then "value" else classification) + ")."

/* 2) Module or class attributes (Attribute) */
from Attribute a, string classification
where
  a.getAnInitializer() instanceof StringLiteral and
  (
    looksLikeSecretName(a.getName(), classification)
    or
    exists(StringLiteral s | s = (StringLiteral) a.getAnInitializer() and looksLikeSecretValue(s))
  )
select a, "Attribute '" + a.getName() + "' is assigned a string literal that looks like a secret (" + (classification = "" then "value" else classification) + ")."

/* 3) Function parameters with default string value */
from FunctionParameter p, string classification
where
  exists(StringLiteral s | s = (StringLiteral) p.getDefaultValue() and
    (
      looksLikeSecretName(p.getName(), classification)
      or looksLikeSecretValue(s)
    )
  )
select p, "Function parameter '" + p.getName() + "' has a string default value that looks like a secret (" + classification + ")."
