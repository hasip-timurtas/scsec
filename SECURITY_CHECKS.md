# Security Checks Reference

This document provides a comprehensive overview of all security checks performed by **solsec**. Each check is designed to identify specific vulnerability patterns in Solana smart contracts.

## Overview

**solsec** performs **8 distinct security checks** across **4 severity levels**:
- 🔴 **Critical**: Immediate security risks requiring urgent attention
- 🟠 **High**: Serious vulnerabilities that should be addressed promptly  
- 🟡 **Medium**: Potential issues that warrant review and consideration
- 🔵 **Low**: Minor concerns or best practice recommendations

---

## 🔴 Critical Severity Checks

### 1. Unchecked Account Access (`unchecked_account`)

**What it detects:**
- Unsafe `mem::transmute` operations on AccountInfo
- Direct pointer operations (`as_ptr`, `as_mut_ptr`) without validation
- Raw account data access followed by unsafe operations
- Use of AccountInfo without proper type validation

**Why it's critical:**
These patterns can lead to memory corruption, type confusion attacks, and arbitrary code execution.

**Examples of vulnerable code:**
```rust
// DANGEROUS: Unsafe transmute without validation
let user_data: &UserData = unsafe {
    mem::transmute(account_data.as_ptr())
};

// DANGEROUS: Direct pointer manipulation
let ptr = account_data.as_mut_ptr() as *mut u64;
unsafe { *ptr = 999999; }

// DANGEROUS: Raw data access with unsafe operations
let data = account_info.try_borrow_data()?;
let balance = unsafe { *(data.as_ptr() as *const u64) };
```

**Secure alternatives:**
```rust
// SAFE: Use typed Account wrapper
let user_account: Account<UserAccount> = Account::try_from(&account_info)?;

// SAFE: Proper deserialization
let user_data = UserData::try_deserialize(&mut account_data.as_ref())?;
```

### 2. Privilege Escalation (`privilege_escalation`)

**What it detects:**
- Authority/admin changes without proper authorization checks
- Owner field modifications without validation
- Privilege modifications without signer verification

**Why it's critical:**
Unauthorized privilege escalation can completely compromise smart contract security.

**Examples of vulnerable code:**
```rust
// DANGEROUS: Admin change without authorization
ctx.accounts.config.admin = new_admin; // No signer check!

// DANGEROUS: Owner change without validation  
account.owner = new_owner; // Anyone can change ownership
```

**Secure alternatives:**
```rust
// SAFE: Verify current admin is signer
require!(ctx.accounts.admin.is_signer, ErrorCode::Unauthorized);
ctx.accounts.config.admin = new_admin;

// SAFE: Proper ownership validation
require!(ctx.accounts.current_owner.is_signer, ErrorCode::NotOwner);
account.owner = new_owner;
```

---

## 🟠 High Severity Checks

### 3. Reentrancy Vulnerabilities (`reentrancy`)

**What it detects:**
- State changes after external calls (`invoke`, `invoke_signed`)
- Cross-program invocation (CPI) followed by state modifications
- Violations of CEI (Checks-Effects-Interactions) pattern

**Why it's high severity:**
Reentrancy attacks can drain funds and manipulate contract state unexpectedly.

**Examples of vulnerable code:**
```rust
// VULNERABLE: State change after external call
invoke(&external_instruction, &accounts)?;
user_account.balance -= amount; // Reentrancy possible here!

// VULNERABLE: Multiple state changes after CPI
invoke_signed(&instruction, &accounts, &[seeds])?;
config.last_operation = Clock::get()?.unix_timestamp;
config.is_locked = false; // Dangerous unlock after external call
```

**Secure alternatives:**
```rust
// SAFE: CEI pattern - Effects before Interactions
user_account.balance -= amount; // State change first
invoke(&external_instruction, &accounts)?; // External call last

// SAFE: Use reentrancy guards
require!(!ctx.accounts.config.is_locked, ErrorCode::Locked);
ctx.accounts.config.is_locked = true;
invoke(&instruction, &accounts)?;
ctx.accounts.config.is_locked = false;
```

### 4. Missing Signer Validation (`missing_signer_check`)

**What it detects:**
- Public instruction handlers without signer validation
- Functions that modify state without authorization checks
- Critical operations accessible to anyone

**Why it's high severity:**
Missing signer checks allow unauthorized users to execute privileged operations.

**Examples of vulnerable code:**
```rust
// VULNERABLE: No signer validation
pub fn transfer_funds(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    // Anyone can call this function!
    ctx.accounts.from.lamports -= amount;
    ctx.accounts.to.lamports += amount;
    Ok(())
}

// VULNERABLE: Admin function without authorization
pub fn update_config(ctx: Context<UpdateConfig>, new_value: u64) -> Result<()> {
    ctx.accounts.config.value = new_value; // No admin check!
    Ok(())
}
```

**Secure alternatives:**
```rust
// SAFE: Proper signer validation
pub fn transfer_funds(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
    ctx.accounts.from.lamports -= amount;
    ctx.accounts.to.lamports += amount;
    Ok(())
}

// SAFE: Admin authorization check
pub fn update_config(ctx: Context<UpdateConfig>, new_value: u64) -> Result<()> {
    require!(
        ctx.accounts.admin.key() == ctx.accounts.config.admin,
        ErrorCode::NotAdmin
    );
    require!(ctx.accounts.admin.is_signer, ErrorCode::Unauthorized);
    ctx.accounts.config.value = new_value;
    Ok(())
}
```

### 5. PDA Validation Issues (`pda_validation`)

**What it detects:**
- PDA seeds without bump parameter validation
- Manual PDA derivation without verification
- Missing canonical PDA enforcement

**Why it's high severity:**
Improper PDA validation can lead to account spoofing and unauthorized access.

**Examples of vulnerable code:**
```rust
// VULNERABLE: Seeds without bump validation
#[account(
    seeds = [b"user", authority.key().as_ref()],
    // Missing bump parameter!
)]
pub user_account: Account<UserAccount>,

// VULNERABLE: Manual derivation without validation
let (pda, _bump) = Pubkey::find_program_address(&seeds, &program_id);
// No validation that this matches expected PDA
```

**Secure alternatives:**
```rust
// SAFE: Include bump validation
#[account(
    seeds = [b"user", authority.key().as_ref()],
    bump, // Ensures canonical PDA
)]
pub user_account: Account<UserAccount>,

// SAFE: Validate derived PDA
let (expected_pda, bump) = Pubkey::find_program_address(&seeds, &program_id);
require!(
    ctx.accounts.user_account.key() == expected_pda,
    ErrorCode::InvalidPDA
);
```

### 6. Insufficient Input Validation (`insufficient_validation`)

**What it detects:**
- Public functions with numeric parameters lacking validation
- Missing bounds checking on user inputs
- Accounts marked for manual validation without implementation

**Why it's high severity:**
Insufficient validation can lead to unexpected behavior and potential exploits.

**Examples of vulnerable code:**
```rust
// VULNERABLE: No input validation
pub fn set_price(ctx: Context<SetPrice>, price: u64) -> Result<()> {
    ctx.accounts.config.price = price; // Could be 0 or MAX_U64!
    Ok(())
}

// VULNERABLE: Manual validation not implemented
/// CHECK: This account needs validation
pub dangerous_account: AccountInfo<'info>,
// No actual validation in function body
```

**Secure alternatives:**
```rust
// SAFE: Proper input validation
pub fn set_price(ctx: Context<SetPrice>, price: u64) -> Result<()> {
    require!(price > 0, ErrorCode::InvalidPrice);
    require!(price <= MAX_REASONABLE_PRICE, ErrorCode::PriceTooHigh);
    ctx.accounts.config.price = price;
    Ok(())
}

// SAFE: Implement manual validation
/// CHECK: Validated to be the correct program
pub program_account: AccountInfo<'info>,

// In function body:
require!(
    program_account.key() == expected_program_id,
    ErrorCode::InvalidProgram
);
```

---

## 🟡 Medium Severity Checks

### 7. Integer Overflow (`integer_overflow`)

**What it detects:**
- Arithmetic operations without overflow protection
- Addition, subtraction, multiplication without checked variants
- Potential overflow in calculations

**Why it's medium severity:**
Integer overflow can cause unexpected behavior but may not always be exploitable.

**Examples of vulnerable code:**
```rust
// VULNERABLE: Unchecked arithmetic
let total = price * quantity; // Could overflow!
let new_balance = old_balance + deposit; // Could wrap around
let remaining = total - fee; // Could underflow
```

**Secure alternatives:**
```rust
// SAFE: Use checked arithmetic
let total = price.checked_mul(quantity)
    .ok_or(ErrorCode::Overflow)?;
let new_balance = old_balance.checked_add(deposit)
    .ok_or(ErrorCode::Overflow)?;
let remaining = total.checked_sub(fee)
    .ok_or(ErrorCode::InsufficientFunds)?;

// SAFE: Use saturating arithmetic where appropriate
let capped_value = value.saturating_add(increment);
```

### 8. Unsafe Arithmetic Operations (`unsafe_arithmetic`)

**What it detects:**
- Division operations without zero checks
- Subtraction that could cause underflow
- Mathematical operations that could panic

**Why it's medium severity:**
These operations can cause runtime panics but are often recoverable.

**Examples of vulnerable code:**
```rust
// VULNERABLE: Division without zero check
let rate = total / time_period; // Panics if time_period is 0

// VULNERABLE: Unchecked subtraction
balance -= withdrawal; // Could underflow and wrap around
```

**Secure alternatives:**
```rust
// SAFE: Check for zero before division
require!(time_period != 0, ErrorCode::InvalidTimePeriod);
let rate = total / time_period;

// SAFE: Use checked subtraction
let new_balance = balance.checked_sub(withdrawal)
    .ok_or(ErrorCode::InsufficientFunds)?;
balance = new_balance;
```

---

## 🔵 Additional Security Validations

### Account Ownership Validation (`account_ownership`)

**What it detects:**
- Unauthorized account ownership changes
- Missing ownership verification

### Lamport Manipulation (`lamport_manipulation`) 

**What it detects:**
- Direct lamport manipulation without authorization
- Potential rent-related vulnerabilities

### Program ID Validation (`program_id_validation`)

**What it detects:**
- Improper program ID access patterns
- Missing program ID verification

---

## Detection Statistics

Based on analysis of the example vulnerability contracts:

| Check Category | Issues Found | Severity Distribution |
|---------------|--------------|----------------------|
| **Unchecked Account** | 18 issues | 4 Critical + 14 Medium |
| **Reentrancy** | 8 issues | 8 High |
| **Missing Signer Check** | 8 issues | 8 High |
| **Integer Overflow** | 5 issues | 5 Medium |
| **PDA Validation** | Active | Various |
| **Privilege Escalation** | Active | Critical/High |
| **Unsafe Arithmetic** | Active | Medium |
| **Insufficient Validation** | Active | High |

**Total Security Coverage:** 39+ vulnerability patterns detected across all severity levels.

---

## Best Practices Summary

### ✅ Always Do:
- Use typed `Account<T>` instead of raw `AccountInfo`
- Implement CEI pattern (Checks-Effects-Interactions)
- Validate all signers before state changes
- Use checked arithmetic operations
- Include bump parameters for PDA validation
- Validate all user inputs with bounds checking

### ❌ Never Do:
- Use `unsafe` operations without thorough validation
- Modify state after external calls
- Allow public functions without authorization
- Perform arithmetic without overflow protection
- Trust unvalidated account data
- Skip input validation on public parameters

---

## Integration with Development Workflow

### Pre-commit Hooks
Automatically run security checks before commits:
```bash
solsec scan ./programs --format json --fail-on-critical
```

### CI/CD Pipeline
Integrate security scanning in continuous integration:
```yaml
- name: Security Scan
  run: solsec scan ./programs --output ./security-results
```

### Development Testing
Regular security validation during development:
```bash
# Quick scan of specific files
solsec scan src/lib.rs

# Comprehensive project scan
solsec scan . --format html --output security-audit
```

---

*This document covers all security checks performed by solsec v0.1.8. For the latest updates and additional checks, refer to the [CHANGELOG.md](CHANGELOG.md).* 