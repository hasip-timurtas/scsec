use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vulnerable_math {
    use super::*;

    pub fn unsafe_add(ctx: Context<Calculate>, a: u64, b: u64) -> Result<()> {
        // VULNERABLE: Direct addition without overflow check
        let result = a + b;
        msg!("Result: {}", result);
        Ok(())
    }

    pub fn unsafe_multiply(ctx: Context<Calculate>, amount: u64, multiplier: u64) -> Result<()> {
        // VULNERABLE: Multiplication without overflow protection
        let total = amount * multiplier;
        ctx.accounts.data.value = total;
        Ok(())
    }

    pub fn unsafe_increment(ctx: Context<Calculate>) -> Result<()> {
        // VULNERABLE: In-place addition without checking
        ctx.accounts.data.value += 1000;
        Ok(())
    }

    pub fn price_calculation(ctx: Context<Calculate>, quantity: u64, price_per_unit: u64) -> Result<()> {
        // VULNERABLE: Could overflow with large quantities
        let total_cost = quantity * price_per_unit;
        
        // Another vulnerable operation
        let fee = total_cost + 100;
        
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