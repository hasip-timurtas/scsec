use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod secure_math {
    use super::*;

    pub fn safe_add(ctx: Context<Calculate>, a: u64, b: u64) -> Result<()> {
        // SECURE: Using checked addition
        let result = a.checked_add(b)
            .ok_or(ErrorCode::MathOverflow)?;
        msg!("Result: {}", result);
        Ok(())
    }

    pub fn safe_multiply(ctx: Context<Calculate>, amount: u64, multiplier: u64) -> Result<()> {
        // SECURE: Using checked multiplication
        let total = amount.checked_mul(multiplier)
            .ok_or(ErrorCode::MathOverflow)?;
        ctx.accounts.data.value = total;
        Ok(())
    }

    pub fn safe_increment(ctx: Context<Calculate>) -> Result<()> {
        // SECURE: Using checked addition for assignment
        ctx.accounts.data.value = ctx.accounts.data.value
            .checked_add(1000)
            .ok_or(ErrorCode::MathOverflow)?;
        Ok(())
    }

    pub fn safe_price_calculation(ctx: Context<Calculate>, quantity: u64, price_per_unit: u64) -> Result<()> {
        // SECURE: All operations use checked arithmetic
        let total_cost = quantity.checked_mul(price_per_unit)
            .ok_or(ErrorCode::MathOverflow)?;
        
        let fee = total_cost.checked_add(100)
            .ok_or(ErrorCode::MathOverflow)?;
        
        ctx.accounts.data.value = fee;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Calculate<'info> {
    #[account(mut)]
    pub data: Account<'info, DataAccount>,
    pub user: Signer<'info>,
}

#[account]
pub struct DataAccount {
    pub value: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Math operation resulted in overflow")]
    MathOverflow,
} 