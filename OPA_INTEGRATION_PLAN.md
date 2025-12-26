# OPA Integration Plan for KProxy

## Overview
Integrate Open Policy Agent (OPA) as an embedded library to externalize policy decision logic from imperative Go code into declarative Rego policies. This will make policy logic more maintainable, testable, and auditable while preserving all existing behavior.

## Current Architecture Analysis

### Decision Points to Externalize
1. **DNS Level (`GetDNSAction`)**:
   - Global bypass pattern matching
   - Device-specific bypass rules
   - Returns: INTERCEPT, BYPASS, or BLOCK

2. **Proxy Level (`Evaluate`)**:
   - Device identification (IP/MAC/CIDR)
   - Time-of-day restrictions
   - Domain/path rule matching with priority
   - Usage limit enforcement
   - Returns: PolicyDecision with Action, Reason, BlockPage, etc.

3. **Helper Functions**:
   - `matchDomain`: Exact, wildcard, and suffix matching
   - `isWithinAllowedTime`: Time window checking
   - `limitApplies`: Usage limit applicability
   - Device identification by IP/MAC/CIDR

## Implementation Steps

### 1. Add OPA Dependency
- Add `github.com/open-policy-agent/opa/rego` to go.mod
- Add `github.com/open-policy-agent/opa/ast` for policy compilation

### 2. Create Rego Policy Structure
Create policy files in `policies/` directory:
- `policies/device.rego` - Device identification logic
- `policies/dns.rego` - DNS action decisions
- `policies/proxy.rego` - Proxy request evaluation
- `policies/time.rego` - Time-based restrictions
- `policies/usage.rego` - Usage limit checking
- `policies/helpers.rego` - Domain matching and utility functions

### 3. Create OPA Engine Wrapper
Create `internal/policy/opa/engine.go`:
- Load and compile Rego policies
- Provide methods for querying policies with structured input
- Handle policy reload on configuration changes
- Manage policy bundle lifecycle

### 4. Define Input/Output Schemas
Document JSON structures for:
- **DNS Query Input**: client_ip, domain, devices, bypass_rules, global_bypass
- **Proxy Request Input**: client_ip, client_mac, host, path, time, device, profile, usage_stats
- **Policy Outputs**: Action, reason, metadata

### 5. Refactor Policy Engine
Modify `internal/policy/engine.go`:
- Initialize OPA engine alongside existing storage
- Replace `GetDNSAction` logic with OPA query
- Replace `Evaluate` logic with OPA query
- Keep data loading logic (devices, profiles, rules) as-is
- Transform loaded data into OPA input format

### 6. Implement Rego Policies

#### Device Identification (`device.rego`)
```rego
package kproxy.device

identify[device] {
    # MAC address matching (highest priority)
    # IP exact matching
    # CIDR range matching
}
```

#### DNS Actions (`dns.rego`)
```rego
package kproxy.dns

action := "BYPASS" {
    # Global bypass check
    # Device-specific bypass check
}

action := "INTERCEPT" {
    # Default action
}
```

#### Proxy Evaluation (`proxy.rego`)
```rego
package kproxy.proxy

decision := {
    "action": action,
    "reason": reason,
    "block_page": block_page,
    "matched_rule_id": rule_id,
    ...
} {
    # Time restrictions
    # Rule evaluation by priority
    # Usage limit checks
    # Default policy
}
```

#### Helpers (`helpers.rego`)
```rego
package kproxy.helpers

match_domain(domain, pattern) {
    # Exact match
    # Wildcard match with regex
    # Suffix match
}

within_time_window(current_time, time_rules) {
    # Day of week check
    # Time of day check
}
```

### 7. Testing Strategy
- Create `internal/policy/opa/engine_test.go` for OPA engine wrapper
- Update `internal/policy/engine_test.go` to verify behavior parity
- Create Rego policy unit tests in `policies/*_test.rego`
- Verify all existing test cases pass

### 8. Configuration Changes
Update `configs/config.example.yaml`:
- Add `policy.opa_bundle_path` for policy directory location
- Optional: Add `policy.opa_decision_log` for OPA decision logging

### 9. Documentation Updates
Update `CLAUDE.md`:
- Document OPA integration architecture
- Explain Rego policy structure
- Update policy evaluation flow diagrams
- Add section on writing/testing Rego policies

## Backwards Compatibility
**NONE REQUIRED** - No backwards compatibility constraints per user requirements.
This allows for:
- Complete refactoring of policy engine internals
- Breaking changes to internal APIs if beneficial
- Removal of old imperative logic after OPA migration

## Success Criteria
1. ✅ All existing tests pass
2. ✅ Policy decisions identical to pre-OPA behavior
3. ✅ Rego policies cover all decision logic
4. ✅ Code is cleaner and more maintainable
5. ✅ Policy changes don't require Go code changes

## Implementation Order
1. Add OPA dependency to go.mod
2. Create policy directory structure and placeholder files
3. Create OPA engine wrapper with basic loading/querying
4. Implement helper.rego (domain matching, time checks)
5. Implement device.rego (device identification)
6. Implement dns.rego (DNS actions)
7. Implement proxy.rego (request evaluation)
8. Implement usage.rego (usage limit checks)
9. Integrate OPA engine into policy.Engine
10. Update tests and verify behavior parity
11. Remove old imperative logic (if fully replaced)
12. Update documentation

## Risks and Mitigations
- **Performance**: OPA queries may add latency
  - *Mitigation*: Benchmark and optimize; OPA is designed for fast in-process evaluation
- **Policy Complexity**: Rego may be harder to debug than Go
  - *Mitigation*: Use OPA's built-in testing and debugging tools; write comprehensive tests
- **Data Transformation**: Converting Go structs to OPA input
  - *Mitigation*: Use structured JSON marshaling; create clear input schemas

## Out of Scope
- External OPA service deployment (embedded only)
- OPA bundle server integration
- Dynamic policy updates without reload
- OPA decision log shipping to external systems
