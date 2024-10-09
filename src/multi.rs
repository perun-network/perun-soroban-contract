use crate::Error;
use alloy_primitives::{
    keccak256, Address as EthAddress, Bytes as PrimBytes, FixedBytes, U256, U64,
};
use alloy_sol_types::sol;
use alloy_sol_types::SolValue;

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
pub enum Chain {
    Stellar = 0,
    Ethereum = 1,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressType {
    Eth(BytesN<20>),
    Stellar(Address),
}
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossAsset {
    pub address: AddressType,
    pub chain: Chain,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelAsset {
    Single(Address),        // Single Asset on Stellar
    Multi(Vec<Address>),    // Multiple Assets on Stellar: Can be crosschain, or not
    Cross(Vec<CrossAsset>), // Crosschain Asset
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelPubKey {
    Single(BytesN<32>),
    Cross(BytesN<65>),
}
impl ChannelPubKey {
    pub fn verify_signature(
        &self,
        env: &Env,
        msg_bytes: &Bytes,
        sig_stellar: &BytesN<64>,
    ) -> Result<(), Error> {
        match self {
            ChannelPubKey::Single(pub_key) => {
                env.crypto()
                    .ed25519_verify(pub_key, &msg_bytes, sig_stellar);
                Ok(())
            }
            ChannelPubKey::Cross(stellar_pub_key) => {
                let rec_id_0: u32 = 0;
                let rec_id_1: u32 = 1;
                let msg_digest = env.crypto().keccak256(&msg_bytes);

                // let eth_prefix = b"\x19Ethereum Signed Message:\n32";
                const ETH_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n32";
                const PREFIX_LEN: usize = 32 + ETH_PREFIX.len();
                let hashstate_bytes: [u8; 32] = msg_digest.into();
                // let prefix_hashstate = [eth_prefix.as_ref(), &hashstate_bytes[..]].concat();
                // let mut prefix_hashstate = [0u8; 32 + eth_prefix.len()];
                let mut prefix_hashstate = [0u8; PREFIX_LEN];

                prefix_hashstate[..ETH_PREFIX.len()].copy_from_slice(ETH_PREFIX);
                prefix_hashstate[ETH_PREFIX.len()..].copy_from_slice(&hashstate_bytes);

                // let prefixhash_slice: &[u8] = prefix_hashstate.as_slice();
                let prefixhash_slice: &[u8] = &prefix_hashstate; //.as_slice();

                let prefixhash_bytes = Bytes::from_slice(env, prefixhash_slice);
                let hashed_msg_with_prefix = env.crypto().keccak256(&prefixhash_bytes);

                let recovered_stellar_pub_key_id_0 =
                    env.crypto()
                        .secp256k1_recover(&hashed_msg_with_prefix, &sig_stellar, rec_id_0);
                let recovered_stellar_pub_key_id_1 =
                    env.crypto()
                        .secp256k1_recover(&hashed_msg_with_prefix, &sig_stellar, rec_id_1);

                if &recovered_stellar_pub_key_id_0 == stellar_pub_key
                    || &recovered_stellar_pub_key_id_1 == stellar_pub_key
                {
                    Ok(())
                } else {
                    return Err(Error::InvalidSignature);
                }
            }
        }
    }

    pub fn verify_signature_cross(
        &self,
        env: &Env,
        msg_bytes: FixedBytes<32>, //&Bytes,
        sig_stellar: &BytesN<64>,
    ) -> Result<(), Error> {
        match self {
            ChannelPubKey::Single(_pub_key) => Err(Error::WrongChannelTypeErr),
            ChannelPubKey::Cross(stellar_pub_key) => {
                let rec_id_0: u32 = 0;
                let rec_id_1: u32 = 1;

                let mut state_sol_abi: [u8; 32] = [0u8; 32];

                let ssl = msg_bytes.as_slice();

                state_sol_abi.copy_from_slice(&ssl);

                let hash_final = BytesN::<32>::from_array(env, &state_sol_abi);

                let recovered_stellar_pub_key_id_0 =
                    env.crypto()
                        .secp256k1_recover(&hash_final, &sig_stellar, rec_id_0);
                let recovered_stellar_pub_key_id_1 =
                    env.crypto()
                        .secp256k1_recover(&hash_final, &sig_stellar, rec_id_1);

                if &recovered_stellar_pub_key_id_0 == stellar_pub_key
                    || &recovered_stellar_pub_key_id_1 == stellar_pub_key
                {
                    Ok(())
                } else {
                    return Err(Error::InvalidSignature);
                }
            }
        }
    }
}

fn compare_keys(recovered: &BytesN<65>, expected: &BytesN<65>) -> bool {
    recovered == expected
}
