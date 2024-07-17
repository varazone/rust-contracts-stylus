#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

use alloc::vec::Vec;

use alloy_primitives::B256;
use crypto::{
    merkle::{self, Verifier},
    KeccakBuilder,
};
use stylus_proc::SolidityError;
use stylus_sdk::{
    alloy_sol_types::sol,
    crypto::keccak,
    prelude::{entrypoint, external, sol_storage},
};

#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

sol! {
    error MerkleProofInvalidMultiProofLength();
    error MerkleProofInvalidRootChild();
    error MerkleProofInvalidTotalHashes();
}

#[derive(SolidityError)]
pub enum VerifierError {
    InvalidProofLength(MerkleProofInvalidMultiProofLength),
    InvalidRootChild(MerkleProofInvalidRootChild),
    InvalidTotalHashes(MerkleProofInvalidTotalHashes),
}

impl core::convert::From<merkle::MultiProofError> for VerifierError {
    fn from(value: merkle::MultiProofError) -> Self {
        match value {
            merkle::MultiProofError::InvalidProofLength => {
                VerifierError::InvalidProofLength(
                    MerkleProofInvalidMultiProofLength {},
                )
            }
            merkle::MultiProofError::InvalidRootChild => {
                VerifierError::InvalidRootChild(MerkleProofInvalidRootChild {})
            }
            merkle::MultiProofError::InvalidTotalHashes => {
                VerifierError::InvalidTotalHashes(
                    MerkleProofInvalidTotalHashes {},
                )
            }
        }
    }
}

sol_storage! {
    #[entrypoint]
    struct VerifierContract { }
}

#[external]
impl VerifierContract {
    pub fn verify(&self, proof: Vec<B256>, root: B256, leaf: B256) -> bool {
        let proof: Vec<[u8; 32]> = proof.into_iter().map(|m| *m).collect();
        verify_native(&proof, *root, *leaf)
    }

    pub fn verify_non_native(
        &self,
        proof: Vec<B256>,
        root: B256,
        leaf: B256,
    ) -> bool {
        let proof: Vec<[u8; 32]> = proof.into_iter().map(|m| *m).collect();
        Verifier::<KeccakBuilder>::verify(&proof, *root, *leaf)
    }

    pub fn verify_multi_proof(
        &self,
        proof: Vec<B256>,
        proof_flags: Vec<bool>,
        root: B256,
        leaves: Vec<B256>,
    ) -> Result<bool, VerifierError> {
        let proof: Vec<[u8; 32]> = proof.into_iter().map(|m| *m).collect();
        let leaves: Vec<[u8; 32]> = leaves.into_iter().map(|m| *m).collect();
        Ok(Verifier::<KeccakBuilder>::verify_multi_proof(
            &proof,
            &proof_flags,
            *root,
            &leaves,
        )?)
    }
}

fn verify_native(
    proof: &[[u8; 32]],
    root: [u8; 32],
    mut leaf: [u8; 32],
) -> bool {
    for &hash in proof {
        leaf = commutative_hash_pair(leaf, hash);
    }

    leaf == root
}

fn commutative_hash_pair(mut a: [u8; 32], mut b: [u8; 32]) -> [u8; 32] {
    if a > b {
        core::mem::swap(&mut a, &mut b);
    }

    *keccak([a, b].concat())
}
