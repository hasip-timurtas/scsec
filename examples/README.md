# Security Vulnerability Examples

This directory contains practical examples demonstrating common security vulnerabilities in Solana smart contracts that **solsec** can detect. Each vulnerability type includes both vulnerable and secure implementations to illustrate the difference.

## 📁 Directory Structure

```
examples/
├── integer_overflow/
│   ├── vulnerable.rs      # Examples that trigger integer overflow detection
│   └── secure.rs          # Safe arithmetic using checked operations
├── missing_signer_check/
│   ├── vulnerable.rs      # Missing authorization validations
│   └── secure.rs          # Proper signer verification patterns
├── unchecked_account/
│   ├── vulnerable.rs      # Unsafe account access patterns
│   └── secure.rs          # Type-safe account handling
├── reentrancy/
│   ├── vulnerable.rs      # State changes after external calls
│   └── secure.rs          # Checks-Effects-Interactions pattern
└── README.md             # This file
```

## 🚨 Vulnerability Types

### 1. Integer Overflow (`integer_overflow`)

**Severity:** Medium

**What it detects:** Arithmetic operations that could overflow without proper checking.

**Vulnerable patterns:**
- Direct arithmetic: `a + b`, `amount * multiplier`
- In-place operations: `value += increment`
- Unchecked calculations in price/fee computations

**Secure patterns:**
- Checked arithmetic: `a.checked_add(b).ok_or(ErrorCode::MathOverflow)?`
- Validated increments: `value.checked_add(increment)`
- Safe multiplication: `quantity.checked_mul(price_per_unit)`

**Example test:**
```bash
solsec scan examples/integer_overflow/vulnerable.rs
# Should detect 4+ issues

solsec scan examples/integer_overflow/secure.rs  
# Should detect 0 issues
```

### 2. Missing Signer Check (`missing_signer_check`)

**Severity:** High

**What it detects:** Instruction handlers that lack proper authorization validation.

**Vulnerable patterns:**
- Functions with "instruction" or "handler" in name without signer validation
- Missing `Signer<'info>` in account contexts
- No verification of caller authority

**Secure patterns:**
- Required `Signer<'info>` accounts
- Authority validation: `require!(account.owner == signer.key())`
- Admin checks: `require!(config.admin == admin.key())`

**Example test:**
```bash
solsec scan examples/missing_signer_check/vulnerable.rs
# Should detect 4+ authorization issues

solsec scan examples/missing_signer_check/secure.rs
# Should detect 0 issues
```

### 3. Unchecked Account (`unchecked_account`)

**Severity:** Critical

**What it detects:** Unsafe account access using `AccountInfo` with `unchecked` or `unsafe` operations.

**Vulnerable patterns:**
- Raw `AccountInfo` with `unsafe` memory operations
- `mem::transmute` for account deserialization
- Direct pointer manipulation: `*ptr = value`
- Unchecked account type assumptions

**Secure patterns:**
- Strongly typed `Account<'info, T>` wrappers
- Anchor's automatic validation
- Type-safe account modification
- Proper initialization constraints

**Example test:**
```bash
solsec scan examples/unchecked_account/vulnerable.rs
# Should detect 4+ critical unsafe operations

solsec scan examples/unchecked_account/secure.rs
# Should detect 0 issues
```

### 4. Reentrancy (`reentrancy`)

**Severity:** High

**What it detects:** State changes after external program calls (`invoke` or `invoke_signed`).

**Vulnerable patterns:**
- `invoke()` followed by state modifications
- `invoke_signed()` with subsequent variable assignments
- Cross-program calls before updating balances/counters

**Secure patterns:**
- Checks-Effects-Interactions pattern
- State changes before external calls
- Reentrancy guards (locks)
- Emergency unlock mechanisms

**Example test:**
```bash
solsec scan examples/reentrancy/vulnerable.rs
# Should detect 4+ reentrancy vulnerabilities

solsec scan examples/reentrancy/secure.rs
# Should detect 0 issues
```

## 🧪 Testing All Examples

Run analysis on all vulnerability examples:

```bash
# Test all vulnerable examples (should find many issues)
solsec scan examples/*/vulnerable.rs

# Test all secure examples (should find few/no issues)
solsec scan examples/*/secure.rs

# Test the entire examples directory
solsec scan examples/

# Generate detailed HTML report
solsec scan examples/ --format html --output examples-report.html
```

## 📊 Expected Results Summary

| Example File | Expected Issues | Primary Detections |
|-------------|----------------|-------------------|
| `integer_overflow/vulnerable.rs` | 4+ | Math operations without checked arithmetic |
| `integer_overflow/secure.rs` | 0 | All operations use `checked_*` methods |
| `missing_signer_check/vulnerable.rs` | 4+ | Functions missing signer validation |
| `missing_signer_check/secure.rs` | 0 | Proper `Signer<'info>` and authorization |
| `unchecked_account/vulnerable.rs` | 4+ | Unsafe `AccountInfo` with `unsafe` operations |
| `unchecked_account/secure.rs` | 0 | Type-safe `Account<'info, T>` usage |
| `reentrancy/vulnerable.rs` | 4+ | State changes after `invoke` calls |
| `reentrancy/secure.rs` | 0 | State changes before external calls |

## 🎯 Learning Objectives

These examples help developers:

1. **Understand Common Vulnerabilities:** See real-world patterns that create security risks
2. **Learn Secure Patterns:** Compare vulnerable vs secure implementations side-by-side
3. **Test Security Tools:** Validate that **solsec** correctly identifies known issues
4. **Practice Code Review:** Train on spotting security anti-patterns
5. **Improve Code Quality:** Apply secure coding practices in your own projects

## 🔧 Using Examples for Development

### As Test Cases
```bash
# Verify rule detection works
for file in examples/*/vulnerable.rs; do
    echo "Testing $file..."
    solsec scan "$file"
done
```

### As Learning Material
1. Read the vulnerable version first
2. Try to identify the security issues manually
3. Run **solsec** to see what it detects
4. Compare with the secure version
5. Understand the mitigation strategies

### As Regression Tests
Use these examples to ensure **solsec** continues working correctly as the codebase evolves.

## 📚 Additional Resources

- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
- [Anchor Security Guidelines](https://book.anchor-lang.com/anchor_in_depth/security.html)
- [Common Solana Vulnerabilities](https://github.com/coral-xyz/sealevel-attacks)

## 🤝 Contributing

When adding new examples:

1. Create both vulnerable and secure versions
2. Add clear comments explaining the security issues
3. Test with **solsec** to ensure detection works
4. Update this README with the new vulnerability type
5. Include expected issue counts in your PR

---

**⚠️ Warning:** The vulnerable examples contain intentional security flaws for educational purposes. **Never use vulnerable patterns in production code.** 