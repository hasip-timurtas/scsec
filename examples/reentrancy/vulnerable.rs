use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vulnerable_reentrancy {
    use super::*;

    // VULNERABLE: State changes after external call
    pub fn withdraw_with_callback(ctx: Context<WithdrawCallback>, amount: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        let vault = &mut ctx.accounts.vault;
        
        // Check balance (but don't update state yet)
        require!(user_account.balance >= amount, ErrorCode::InsufficientBalance);
        
        // DANGEROUS: External call before state update
        let instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.callback_program.key(),
            accounts: vec![],
            data: vec![],
        };
        
        invoke(
            &instruction,
            &[ctx.accounts.callback_program.clone()],
        )?;
        
        // VULNERABLE: State changes after external call - reentrancy possible!
        user_account.balance -= amount;
        vault.total_withdrawn += amount;
        
        Ok(())
    }

    // VULNERABLE: Multiple state changes after invoke
    pub fn complex_withdraw(ctx: Context<ComplexWithdraw>, amount: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        let pool = &mut ctx.accounts.pool;
        
        // External call to notify other program
        let notify_instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.external_program.key(),
            accounts: vec![],
            data: amount.to_le_bytes().to_vec(),
        };
        
        invoke(
            &notify_instruction,
            &[ctx.accounts.external_program.clone()],
        )?;
        
        // VULNERABLE: Multiple state updates after external call
        user_account.balance -= amount;
        user_account.last_withdrawal = Clock::get()?.unix_timestamp;
        pool.total_balance -= amount;
        pool.withdrawal_count += 1;
        
        Ok(())
    }

    // VULNERABLE: Cross-program invocation with state changes
    pub fn transfer_with_hook(ctx: Context<TransferWithHook>, amount: u64) -> Result<()> {
        let from_account = &mut ctx.accounts.from_account;
        let to_account = &mut ctx.accounts.to_account;
        
        // DANGEROUS: Call external program first
        let hook_instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.hook_program.key(),
            accounts: vec![],
            data: vec![1, 2, 3], // Some hook data
        };
        
        invoke(
            &hook_instruction,
            &[ctx.accounts.hook_program.clone()],
        )?;
        
        // VULNERABLE: State changes after external call
        from_account.balance -= amount;
        to_account.balance += amount;
        from_account.transfer_count += 1;
        
        Ok(())
    }

    // VULNERABLE: Signed invoke with subsequent state changes
    pub fn privileged_operation(ctx: Context<PrivilegedOp>, data: Vec<u8>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // External privileged call
        let seeds = &[
            b"authority",
            &[ctx.bumps.authority],
        ];
        
        let privileged_instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.external_program.key(),
            accounts: vec![],
            data,
        };
        
        invoke_signed(
            &privileged_instruction,
            &[ctx.accounts.external_program.clone()],
            &[seeds],
        )?;
        
        // VULNERABLE: Critical state changes after external call
        config.last_operation = Clock::get()?.unix_timestamp;
        config.operation_count += 1;
        config.is_locked = false; // Dangerous unlock after external call
        
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

#[account]
pub struct UserAccount {
    pub balance: u64,
    pub last_withdrawal: i64,
    pub transfer_count: u64,
}

#[account]
pub struct Vault {
    pub total_withdrawn: u64,
}

#[account]
pub struct Pool {
    pub total_balance: u64,
    pub withdrawal_count: u64,
}

#[account]
pub struct Config {
    pub last_operation: i64,
    pub operation_count: u64,
    pub is_locked: bool,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient balance")]
    InsufficientBalance,
} 