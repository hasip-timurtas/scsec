use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vulnerable_auth {
    use super::*;

    // VULNERABLE: No signer validation - anyone can call this
    pub fn transfer_funds_handler(ctx: Context<TransferFunds>, amount: u64) -> Result<()> {
        let from_account = &mut ctx.accounts.from;
        let to_account = &mut ctx.accounts.to;
        
        // Missing check: who is authorized to make this transfer?
        from_account.balance -= amount;
        to_account.balance += amount;
        
        Ok(())
    }

    // VULNERABLE: Admin function without proper authorization
    pub fn admin_instruction(ctx: Context<AdminAction>, new_admin: Pubkey) -> Result<()> {
        // Anyone can call this and change the admin!
        ctx.accounts.config.admin = new_admin;
        Ok(())
    }

    // VULNERABLE: Withdrawal without verifying the caller
    pub fn withdraw_handler(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // No verification that the caller owns this account
        ctx.accounts.user_account.balance -= amount;
        Ok(())
    }

    // VULNERABLE: Update critical data without authorization
    pub fn update_price_instruction(ctx: Context<UpdatePrice>, new_price: u64) -> Result<()> {
        // Oracle price update without verifying authority
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
    // Missing: pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    // Missing signer validation
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    // Missing: pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdatePrice<'info> {
    #[account(mut)]
    pub price_feed: Account<'info, PriceFeed>,
    // Missing oracle authority validation
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