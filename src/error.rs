use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauhotized")]
    Unauthorized(),

    #[error("Admin not found")]
    AdminNotFound(),

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

    #[error("Escrow already existsr")]
    EscrowAlreadyExists,

    #[error("Did document controller not existsr")]
    DidDocumentControllerNotExists,

    #[error("Did document service already existsr")]
    DidDocumentServiceAlreadyExists,

    #[error("Did document service not existsr")]
    DidDocumentServiceNotExists,
}