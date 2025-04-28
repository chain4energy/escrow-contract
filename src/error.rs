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

    #[error("No coins")]
    NoCoins,

    #[error("Coins not match: expected {0} != got {1}")]
    CoinsMismatch(String, String),

    #[error("Unauthorized")]
    Unauthorized(),

    #[error("Admin not found")]
    AdminNotFound(),

    #[error("Admin already exists")]
    AdminAlreadyExists(),

    #[error("At least one contract admin is required")]
    NoAdmin,

    #[error("Invalid admin address: {0}")]
    InvalidAdminAddress(StdError),

    #[error("At least one controller is required")]
    ControllerRequired(),

    #[error("Controller does not exist")]
    ControllerDoesNotExist(),

    #[error("Escrow operator not found")]
    EscrowOperatorNotFound(StdError),

    #[error("Escrow not found: {0}")]
    EscrowNotFound(String),

    #[error("Escrow error: {0}: {1}")]
    EscrowError(String, StdError),

    #[error("Escrow has expired")]
    EscrowExpired,

    #[error("Escrow operator error: {0}: {1}")]
    EscrowOperatorError(String, StdError),

    #[error("Operator does not extist")]
    OperatorNotExists,

    #[error("Did document - wrong owner")]
    DidDocumentWrongOwner,

    #[error("Operator already exists")]
    OperatorAlreadyExists,

    
    #[error("Operator does not exist")]
    OperatorDoesNotExist,

    #[error("Escrow already exists")]
    EscrowAlreadyExists,

    #[error("Did document controller not exist")]
    DidDocumentControllerNotExists,

    #[error("Did document service already exist")]
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

    #[error("Escrow wrong state: expected {expected}, but got {got}")]
    EscrowWrongState {
        expected: String,
        got: String,
    },

    #[error("Some Error")]
    SomeError, // TODO  specify error

    #[error("Invalid address: {0}")]
    InvalidAddress(StdError),

    #[error("Duplicated admin: {0}")]
    DuplicatedAdmin(String),

    #[error("Duplicated controller: {0}")]
    DuplicatedController(String),

    #[error("Did contract address error: {0}: {1}")]
    DidContractAddressError(String, StdError),

    #[error("Escrow operator disabled: {0}")]
    EscowOperatorDisabled(String),

    #[error("Escrow operator enabled: {0}")]
    EscowOperatorEnabled(String),


    #[error("Admin error: {0}: {1}")]
    AdminError(String, StdError),

    #[error("Load timeout error: {0}: {1}")]
    LoadTimeoutError(String, StdError),
    // #[error("Coins Error")]
    // CoinsError(CoinsError), // TODO  specify error
}