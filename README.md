# opa-S3-auth
A rego policy could be bypassed, if there are vulnerabilities.

1. Role Spoofing: We will need to ensure the role is validated and comes from a trusted source.

2. Case Sensivity:
If the role is case sensitive , different casing can bypass the rule. To mitigate, we should normalize the role to a standard
case (eg lowercase).

3. Too many Permissive Conditions:
If the policy hass too many permissive conditions, it might allow unintended access, we sholud follow best-practice (strict and only least privileges allowed)

4. Incomplete Input Validation:
If the policy doesn't check for the presence of necessary fields, An attacker can bypass the policy by omitting them. Mitigate by ensuring all necessary fields are present and valid. 

Tested some Edge Cases in policy_test.rego 
if a role is not provided, role is with different casings or if additional fields not expected is in the input.