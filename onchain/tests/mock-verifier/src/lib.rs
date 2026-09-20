#![forbid(unsafe_code)]

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

solana_program::declare_id!("DQEtWAqhL651Pyk2VpvXoYhVtR5f8canQVKiYAQsJfE8");

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first() {
        Some(1) => Ok(()),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
