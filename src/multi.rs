use crate::Error;

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Chain {
    Stellar,
    Ethereum,
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
    Cross(BytesN<65>, BytesN<65>),
}

impl ChannelPubKey {
    pub fn verify_signature(
        &self,
        env: &Env,
        msg_bytes: &Bytes,
        sig_stellar: &BytesN<64>,
        sig_eth: &BytesN<64>,
    ) -> Result<(), Error> {
        match self {
            ChannelPubKey::Single(pub_key) => {
                env.crypto()
                    .ed25519_verify(pub_key, &msg_bytes, sig_stellar);
                Ok(())
            }
            ChannelPubKey::Cross(stellar_pub_key, eth_pub_key) => {
                let rec_id_0: u32 = 0;
                let rec_id_1: u32 = 1;
                let msg_digest = env.crypto().keccak256(&msg_bytes);

                let eth_prefix = b"\x19Ethereum Signed Message:\n32";
                let hashstate_bytes: [u8; 32] = msg_digest.into();
                let prefix_hashstate = [eth_prefix.as_ref(), &hashstate_bytes[..]].concat();
                let prefixhash_slice: &[u8] = prefix_hashstate.as_slice();
                let prefixhash_bytes = Bytes::from_slice(env, prefixhash_slice);
                let hashed_msg_with_prefix = env.crypto().keccak256(&prefixhash_bytes);

                let recovered_stellar_pub_key_id_0 =
                    env.crypto()
                        .secp256k1_recover(&hashed_msg_with_prefix, &sig_stellar, rec_id_0);
                let recovered_stellar_pub_key_id_1 =
                    env.crypto()
                        .secp256k1_recover(&hashed_msg_with_prefix, &sig_stellar, rec_id_1);

                if &recovered_stellar_pub_key_id_0 != stellar_pub_key
                    && &recovered_stellar_pub_key_id_1 != stellar_pub_key
                {
                    return Err(Error::InvalidSignature);
                }

                let recovered_eth_pub_key_id_0 =
                    env.crypto()
                        .secp256k1_recover(&hashed_msg_with_prefix, &sig_eth, rec_id_0);
                let recovered_eth_pub_key_id_1 =
                    env.crypto()
                        .secp256k1_recover(&hashed_msg_with_prefix, &sig_eth, rec_id_1);

                if &recovered_eth_pub_key_id_0 == eth_pub_key
                    || &recovered_eth_pub_key_id_1 == eth_pub_key
                {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
        }
    }
}

fn compare_keys(recovered: &BytesN<65>, expected: &BytesN<65>) -> bool {
    recovered == expected
}
