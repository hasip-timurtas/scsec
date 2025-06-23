use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod secure_accounts {
    use super::*;

    // SECURE: Proper account validation and type checking
    pub fn process_validated_account(ctx: Context<ProcessAccount>) -> Result<()> {
        let user_account = &ctx.accounts.target_account;
        
        // SECURE: Using strongly typed Account wrapper with automatic validation
        msg!("Processing validated balance: {}", user_account.balance);
        
        // Additional validation if needed
        require!(
            user_account.authority == ctx.accounts.authority.key(),
            ErrorCode::InvalidAuthority
        );
        
        Ok(())
    }

    // SECURE: Safe account access with proper validation
    pub fn safe_account_operation(ctx: Context<SafeOperation>) -> Result<()> {
        let data_account = &ctx.accounts.data_account;
        
        // SECURE: Account type is validated by Anchor
        // No unsafe operations needed
        msg!("Safe access to balance: {}", data_account.balance);
        
        // Any additional business logic validation
        require!(
            data_account.balance > 0,
            ErrorCode::InvalidBalance
        );
        
        Ok(())
    }

    // SECURE: Proper account modification with validation
    pub fn safe_account_modification(ctx: Context<SafeModification>) -> Result<()> {
        let target_account = &mut ctx.accounts.target_account;
        
        // SECURE: Type-safe modification through Account wrapper
        require!(
            target_account.authority == ctx.accounts.authority.key(),
            ErrorCode::Unauthorized
        );
        
        // Safe modification
        target_account.balance = target_account.balance
            .checked_add(100)
            .ok_or(ErrorCode::MathOverflow)?;
        
        Ok(())
    }

    // SECURE: Multiple account validation
    pub fn validate_multiple_accounts(ctx: Context<MultipleAccounts>) -> Result<()> {
        let from_account = &ctx.accounts.from_account;
        let to_account = &ctx.accounts.to_account;
        
        // SECURE: All accounts are properly typed and validated
        require!(
            from_account.authority == ctx.accounts.authority.key(),
            ErrorCode::InvalidFromAccount
        );
        
        require!(
            to_account.is_initialized,
            ErrorCode::AccountNotInitialized
        );
        
        msg!("Validated accounts - From: {}, To: {}", 
             from_account.balance, to_account.balance);
        
        Ok(())
    }

    // SECURE: Account initialization with proper validation
    pub fn initialize_account(ctx: Context<InitializeAccount>) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        
        // SECURE: Proper initialization
        user_account.balance = 0;
        user_account.authority = ctx.accounts.authority.key();
        user_account.is_initialized = true;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ProcessAccount<'info> {
    // SECURE: Strongly typed account with automatic validation
    pub target_account: Account<'info, UserAccount>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SafeOperation<'info> {
    // SECURE: Account type enforced by Anchor
    pub data_account: Account<'info, UserAccount>,
}

#[derive(Accounts)]
pub struct SafeModification<'info> {
    // SECURE: Mutable access with type safety
    #[account(mut)]
    pub target_account: Account<'info, UserAccount>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct MultipleAccounts<'info> {
    // SECURE: All accounts properly typed
    pub from_account: Account<'info, UserAccount>,
    pub to_account: Account<'info, UserAccount>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction()]
pub struct InitializeAccount<'info> {
    // SECURE: Account initialization with proper constraints
    #[account(
        init,
        payer = authority,
        space = 8 + UserAccount::INIT_SPACE
    )]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub balance: u64,
    pub authority: Pubkey,
    pub is_initialized: bool,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid authority for this account")]
    InvalidAuthority,
    #[msg("Account balance is invalid")]
    InvalidBalance,
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Math operation resulted in overflow")]
    MathOverflow,
    #[msg("Invalid from account")]
    InvalidFromAccount,
    #[msg("Account is not properly initialized")]
    AccountNotInitialized,
} 