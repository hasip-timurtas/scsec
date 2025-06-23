use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod secure_auth {
    use super::*;

    // SECURE: Proper signer validation for transfers
    pub fn transfer_funds_handler(ctx: Context<TransferFunds>, amount: u64) -> Result<()> {
        let from_account = &mut ctx.accounts.from;
        let to_account = &mut ctx.accounts.to;
        
        // SECURE: Verify the signer owns the from account
        require!(
            from_account.owner == ctx.accounts.authority.key(),
            ErrorCode::UnauthorizedTransfer
        );
        
        // Additional security: Check sufficient balance
        require!(
            from_account.balance >= amount,
            ErrorCode::InsufficientBalance
        );
        
        from_account.balance -= amount;
        to_account.balance += amount;
        
        Ok(())
    }

    // SECURE: Admin function with proper authorization
    pub fn admin_instruction(ctx: Context<AdminAction>, new_admin: Pubkey) -> Result<()> {
        // SECURE: Verify the current admin is signing
        require!(
            ctx.accounts.config.admin == ctx.accounts.admin.key(),
            ErrorCode::UnauthorizedAdmin
        );
        
        ctx.accounts.config.admin = new_admin;
        Ok(())
    }

    // SECURE: Withdrawal with proper ownership verification
    pub fn withdraw_handler(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // SECURE: Verify the signer owns the account
        require!(
            ctx.accounts.user_account.owner == ctx.accounts.user.key(),
            ErrorCode::UnauthorizedWithdrawal
        );
        
        require!(
            ctx.accounts.user_account.balance >= amount,
            ErrorCode::InsufficientBalance
        );
        
        ctx.accounts.user_account.balance -= amount;
        Ok(())
    }

    // SECURE: Oracle price update with authority validation
    pub fn update_price_instruction(ctx: Context<UpdatePrice>, new_price: u64) -> Result<()> {
        // SECURE: Verify the oracle authority is signing
        require!(
            ctx.accounts.price_feed.oracle == ctx.accounts.oracle.key(),
            ErrorCode::UnauthorizedOracle
        );
        
        ctx.accounts.price_feed.price = new_price;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferFunds<'info> {
    #[account(mut)]
    pub from: Account<'info, UserAccount>,
    #[account(mut)]
    pub to: Account<'info, UserAccount>,
    pub authority: Signer<'info>, // SECURE: Required signer
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>, // SECURE: Admin must sign
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    pub user: Signer<'info>, // SECURE: User must sign
}

#[derive(Accounts)]
pub struct UpdatePrice<'info> {
    #[account(mut)]
    pub price_feed: Account<'info, PriceFeed>,
    pub oracle: Signer<'info>, // SECURE: Oracle must sign
}

#[account]
pub struct UserAccount {
    pub balance: u64,
    pub owner: Pubkey,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
}

#[account]
pub struct PriceFeed {
    pub price: u64,
    pub oracle: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized transfer attempt")]
    UnauthorizedTransfer,
    #[msg("Insufficient balance for operation")]
    InsufficientBalance,
    #[msg("Unauthorized admin operation")]
    UnauthorizedAdmin,
    #[msg("Unauthorized withdrawal attempt")]
    UnauthorizedWithdrawal,
    #[msg("Unauthorized oracle price update")]
    UnauthorizedOracle,
} 