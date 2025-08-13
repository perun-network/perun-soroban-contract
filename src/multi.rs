use crate::Error;
use alloy_primitives::FixedBytes;

use soroban_sdk::{contracttype, Address, BytesN, Env};
use soroban_sdk::crypto::Hash;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]

pub struct Chain(u64);

impl Chain {
    pub fn new(value: u64) -> Self {
        Chain(value)
    }
    pub fn as_u64(&self) -> u64 {
        // Use `u64` here to avoid data loss
        self.0
    }
}
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossAsset {
    pub chain: Chain,
    pub stellar_address: Address,
    pub eth_address: BytesN<20>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelPubKeyCross {
    pub key: BytesN<65>,
}

impl ChannelPubKeyCross {
    pub fn verify_signature_cross(
        &self,
        env: &Env,
        msg_bytes: Hash<32>, //&Bytes,
        sig_stellar: &BytesN<65>,
    ) -> Result<(), Error> {
        let rec_id_0: u32 = 0;
        let rec_id_1: u32 = 1;

        let sig_eth_bytes = &sig_stellar.to_array();
        let mut sig_trimmed: [u8; 64] = [0u8; 64];
        sig_trimmed.copy_from_slice(&sig_eth_bytes[0..64]);

        let sig_bytes = BytesN::<64>::from_array(&env, &sig_trimmed);
        let recovered_pub_key_id_0 =
            env.crypto()
                .secp256k1_recover(&msg_bytes, &sig_bytes, rec_id_0);
        let recovered_pub_key_id_1 =
            env.crypto()
                .secp256k1_recover(&msg_bytes, &sig_bytes, rec_id_1);

        if &recovered_pub_key_id_0 == &self.key || &recovered_pub_key_id_1 == &self.key {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
