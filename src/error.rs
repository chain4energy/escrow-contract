use cosmwasm_std::{CoinsError, StdError, Uint128};
use thiserror::Error;
use did_contract::error::ContractError as DidError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    DidError(#[from] DidError),

    #[error("{0}")]
    CoinsError(#[from] CoinsError),

    #[error("Unauhotized")]
    Unauthorized(),

    #[error("Admin not found")]
    AdminNotFound(),

    #[error("Admin already exists")]
    AdminAlreadyExists(),

    #[error("At least one controller is required")]
    ControllerRequired(),

    #[error("Controller does not exist")]
    ControllerDoesNotExist(),

    #[error("Escrow operator not found")]
    EscrowOperatorNotFound(StdError),

    #[error("Escrow not found")]
    EscrowNotFound(StdError),

    #[error("Escrow error")]
    EscrowError(StdError),

    #[error("Escrow operator error")]
    EscrowOperatorError(StdError),

    #[error("Operator does not extist")]
    OperatorNotExists,

    #[error("Did document - wrong owner")]
    DidDocumentWrongOwner,

    #[error("Operator already existsr")]
    OperatorAlreadyExists,

    
    #[error("Operator does not exist")]
    OperatorDoesNotExist,

    #[error("Escrow already existsr")]
    EscrowAlreadyExists,

    #[error("Did document controller not existsr")]
    DidDocumentControllerNotExists,

    #[error("Did document service already existsr")]
    DidDocumentServiceAlreadyExists,

    #[error("Did document service not existsr")]
    DidDocumentServiceNotExists,

    #[error("Share must be [0,1]")]
    ShareValue,

    #[error("Insufficient funds: required {required} {denom}, but only {available} is available")]
    InsufficientFunds {
        denom: String,
        required: Uint128,
        available: Uint128,
    },

    #[error("Escrow wring state")]
    EscrowWrongSate(),

    #[error("Some Error")]
    SomeError, // TODO  specify error


    // #[error("Coins Error")]
    // CoinsError(CoinsError), // TODO  specify error
}