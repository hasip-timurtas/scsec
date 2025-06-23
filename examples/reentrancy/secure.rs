use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod secure_reentrancy {
    use super::*;

    // SECURE: State changes before external call
    pub fn secure_withdraw_with_callback(ctx: Context<WithdrawCallback>, amount: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        let vault = &mut ctx.accounts.vault;
        
        // Validation
        require!(user_account.balance >= amount, ErrorCode::InsufficientBalance);
        require!(!vault.is_locked, ErrorCode::VaultLocked);
        
        // SECURE: State changes BEFORE external call
        user_account.balance -= amount;
        vault.total_withdrawn += amount;
        vault.is_locked = true; // Reentrancy guard
        
        // External call after state is updated
        let instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.callback_program.key(),
            accounts: vec![],
            data: vec![],
        };
        
        let result = invoke(
            &instruction,
            &[ctx.accounts.callback_program.clone()],
        );
        
        // Unlock after external call
        vault.is_locked = false;
        
        result?;
        Ok(())
    }

    // SECURE: All state changes before external interactions
    pub fn secure_complex_withdraw(ctx: Context<ComplexWithdraw>, amount: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        let pool = &mut ctx.accounts.pool;
        
        // Validation
        require!(user_account.balance >= amount, ErrorCode::InsufficientBalance);
        require!(!pool.is_processing, ErrorCode::OperationInProgress);
        
        // SECURE: Complete all state changes before external call
        user_account.balance -= amount;
        user_account.last_withdrawal = Clock::get()?.unix_timestamp;
        pool.total_balance -= amount;
        pool.withdrawal_count += 1;
        pool.is_processing = true; // Reentrancy guard
        
        // External call after all state updates
        let notify_instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.external_program.key(),
            accounts: vec![],
            data: amount.to_le_bytes().to_vec(),
        };
        
        let result = invoke(
            &notify_instruction,
            &[ctx.accounts.external_program.clone()],
        );
        
        // Clear processing flag
        pool.is_processing = false;
        
        result?;
        Ok(())
    }

    // SECURE: Checks-Effects-Interactions pattern
    pub fn secure_transfer_with_hook(ctx: Context<TransferWithHook>, amount: u64) -> Result<()> {
        let from_account = &mut ctx.accounts.from_account;
        let to_account = &mut ctx.accounts.to_account;
        
        // CHECKS: All validations first
        require!(from_account.balance >= amount, ErrorCode::InsufficientBalance);
        require!(
            from_account.authority == ctx.accounts.authority.key(),
            ErrorCode::Unauthorized
        );
        require!(!from_account.is_locked, ErrorCode::AccountLocked);
        
        // EFFECTS: All state changes before external interactions
        from_account.balance -= amount;
        to_account.balance += amount;
        from_account.transfer_count += 1;
        from_account.is_locked = true; // Prevent reentrancy
        
        // INTERACTIONS: External calls last
        let hook_instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.hook_program.key(),
            accounts: vec![],
            data: vec![1, 2, 3],
        };
        
        let result = invoke(
            &hook_instruction,
            &[ctx.accounts.hook_program.clone()],
        );
        
        // Unlock after external call
        from_account.is_locked = false;
        
        result?;
        Ok(())
    }

    // SECURE: Privileged operation with proper state management
    pub fn secure_privileged_operation(ctx: Context<PrivilegedOp>, data: Vec<u8>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // Validation and reentrancy protection
        require!(!config.is_locked, ErrorCode::ConfigLocked);
        
        // SECURE: Update state before external call
        config.last_operation = Clock::get()?.unix_timestamp;
        config.operation_count += 1;
        config.is_locked = true; // Lock during operation
        
        // External call with signed invoke
        let seeds = &[
            b"authority",
            &[ctx.bumps.authority],
        ];
        
        let privileged_instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.external_program.key(),
            accounts: vec![],
            data,
        };
        
        let result = invoke_signed(
            &privileged_instruction,
            &[ctx.accounts.external_program.clone()],
            &[seeds],
        );
        
        // Only unlock on success
        if result.is_ok() {
            config.is_locked = false;
        }
        
        result?;
        Ok(())
    }

    // SECURE: Emergency function to unlock if needed
    pub fn emergency_unlock(ctx: Context<EmergencyUnlock>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        require!(
            ctx.accounts.emergency_authority.key() == config.emergency_key,
            ErrorCode::Unauthorized
        );
        
        config.is_locked = false;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawCallback<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: External program for callback
    pub callback_program: AccountInfo<'info>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct ComplexWithdraw<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    /// CHECK: External program
    pub external_program: AccountInfo<'info>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferWithHook<'info> {
    #[account(mut)]
    pub from_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub to_account: Account<'info, UserAccount>,
    /// CHECK: Hook program
    pub hook_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct PrivilegedOp<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    /// CHECK: External program
    pub external_program: AccountInfo<'info>,
    #[account(
        seeds = [b"authority"],
        bump
    )]
    /// CHECK: PDA authority
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct EmergencyUnlock<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub emergency_authority: Signer<'info>,
}

#[account]
pub struct UserAccount {
    pub balance: u64,
    pub last_withdrawal: i64,
    pub transfer_count: u64,
    pub authority: Pubkey,
    pub is_locked: bool,
}

#[account]
pub struct Vault {
    pub total_withdrawn: u64,
    pub is_locked: bool,
}

#[account]
pub struct Pool {
    pub total_balance: u64,
    pub withdrawal_count: u64,
    pub is_processing: bool,
}

#[account]
pub struct Config {
    pub last_operation: i64,
    pub operation_count: u64,
    pub is_locked: bool,
    pub emergency_key: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient balance")]
    InsufficientBalance,
    #[msg("Vault is currently locked")]
    VaultLocked,
    #[msg("Operation already in progress")]
    OperationInProgress,
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Account is locked")]
    AccountLocked,
    #[msg("Config is locked")]
    ConfigLocked,
} 