use anchor_lang::prelude::*;
use std::mem;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vulnerable_accounts {
    use super::*;

    // VULNERABLE: Using unchecked account deserialization
    pub fn process_unchecked_account(ctx: Context<ProcessAccount>) -> Result<()> {
        let account_info = &ctx.accounts.target_account;
        
        // DANGEROUS: Direct access to account data without validation
        let account_data = account_info.try_borrow_data()?;
        let user_data: &UserData = unsafe {
            mem::transmute(account_data.as_ptr())
        };
        
        // Using potentially corrupted/invalid data
        msg!("Processing balance: {}", user_data.balance);
        Ok(())
    }

    // VULNERABLE: Unsafe account access
    pub fn unsafe_account_operation(ctx: Context<UnsafeOperation>) -> Result<()> {
        let account_info = &ctx.accounts.data_account;
        
        // DANGEROUS: Unchecked cast to specific account type
        let raw_data = account_info.try_borrow_data()?;
        let account_data = unsafe {
            std::slice::from_raw_parts(
                raw_data.as_ptr() as *const u64,
                raw_data.len() / 8
            )
        };
        
        // Could read garbage data or cause memory violations
        if !account_data.is_empty() {
            msg!("First value: {}", account_data[0]);
        }
        
        Ok(())
    }

    // VULNERABLE: Direct AccountInfo manipulation
    pub fn manipulate_account_directly(ctx: Context<DirectManipulation>) -> Result<()> {
        let account_info = &ctx.accounts.target_account;
        
        // DANGEROUS: Direct write to account without proper validation
        let mut account_data = account_info.try_borrow_mut_data()?;
        unsafe {
            let ptr = account_data.as_mut_ptr() as *mut u64;
            *ptr = 999999; // Could corrupt account structure
        }
        
        Ok(())
    }

    // VULNERABLE: Unchecked program account access
    pub fn unchecked_program_access(ctx: Context<ProgramAccess>) -> Result<()> {
        let account_info = &ctx.accounts.unknown_account;
        
        // DANGEROUS: No verification this is the expected account type
        if account_info.data_len() > 0 {
            let data = account_info.try_borrow_data()?;
            // Assuming it's our account type without validation
            let balance = unsafe { *(data.as_ptr() as *const u64) };
            msg!("Unchecked balance: {}", balance);
        }
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ProcessAccount<'info> {
    /// CHECK: This is dangerous - no validation of account type
    pub target_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UnsafeOperation<'info> {
    /// CHECK: Unsafe - could be any account
    pub data_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DirectManipulation<'info> {
    /// CHECK: No validation - direct manipulation
    #[account(mut)]
    pub target_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ProgramAccess<'info> {
    /// CHECK: Unchecked account access
    pub unknown_account: AccountInfo<'info>,
}

#[repr(C)]
pub struct UserData {
    pub balance: u64,
    pub authority: Pubkey,
} 