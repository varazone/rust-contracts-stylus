#![cfg(feature = "e2e")]

use abi::Crypto;
use alloy::{
    primitives::{
        address, eip191_hash_message, fixed_bytes, utils::eip191_message,
        Address, FixedBytes, B256,
    },
    sol,
    sol_types::SolConstructor,
};
use e2e::{Account, Revert};
use eyre::Result;

mod abi;

sol!("src/constructor.sol");

async fn deploy(account: &Account) -> eyre::Result<Address> {
    e2e::deploy(account.url(), &account.pk(), None).await
}

fn hash(message: &[u8]) -> B256 {
    eip191_hash_message(message)
}

// ============================================================================
// Integration Tests: ECDSA
// ============================================================================

const MESSAGE: FixedBytes<32> = fixed_bytes!(
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
);

// #[e2e::test]
// async fn recovers_from_v_r_s(alice: Account) -> Result<()> {
//     let contract_addr = deploy(&alice).await?;
//     let contract = Crypto::new(contract_addr, &alice.wallet);
//
//     let hash = hash(&*MESSAGE);
//     let signature = alice.sign_hash(&hash).await;
//
//     let recovered =
//         signature.recover_address_from_msg(MESSAGE).expect("should recover");
//     assert_eq!(recovered, alice.address());
//
//     let Crypto::recover_2Return { recovered } = contract
//         .recover_2(
//             hash,
//             signature.v().to_u64() as u8,
//             signature.r().into(),
//             signature.s().into(),
//         )
//         .call()
//         .await?;
//
//     assert_eq!(alice.address(), recovered);
//
//     Ok(())
// }

sol! {
    #[sol(rpc)]
    contract Ecrecover {
        function ecrecover(
            bytes32 hash,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) returns (address recovered);
    }
}

type Input = sol! {
    tuple(bytes32,uint8,bytes32,bytes32)
};

#[e2e::test]
async fn recovers_from_signature(alice: Account) -> Result<()> {
    let contract_addr = deploy(&alice).await?;
    let contract = Crypto::new(contract_addr, &alice.wallet);

    let h = eip191_hash_message(MESSAGE);
    println!("h {:?}", h);
    let hash = hash(&*MESSAGE);
    println!("hash {:?}", hash);
    let signature = alice.sign_hash(&hash).await;
    println!("signature {:?}", signature);

    let recovered =
        signature.recover_address_from_msg(MESSAGE).expect("should recover");
    assert_eq!(recovered, alice.address());
    println!("recovered {:?}", recovered);

    let v = signature.v().to_u64() as u8;
    let r = signature.r();
    let s = signature.s();

    const ECRECOVER_ADDR: Address =
        address!("0000000000000000000000000000000000000001");

    let contract = Ecrecover::new(ECRECOVER_ADDR, &alice.wallet);
    let r = contract.ecrecover(hash, v, r.into(), s.into()).call().await;
    println!("recovered {:?}", recovered);
    // let Crypto::recover_2Return { recovered } =
    //     contract.recover_2(hash, v, r.into(), s.into()).call().await?;

    assert_eq!(alice.address(), recovered);

    Ok(())
}
