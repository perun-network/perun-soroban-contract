#![no_std]
use crate::Error;
use crate::Participant;

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, xdr::ToXdr, Address,
    Bytes, BytesN, Env,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
// This defines a channel address that is derived from a public
// pub struct EthAddress(pub [u8; 20]);
pub struct MultiAddress(pub BytesN<20>);

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelAsset {
    Single(Address),
    Multi(Address, MultiAddress),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelAddress {
    Single(Address),
    Multi(Address, MultiAddress),
}
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChannelPubKey {
    Single(BytesN<32>),
    Multi(BytesN<65>),
}

impl ChannelPubKey {
    pub fn verify_signature(
        &self,
        env: &Env,
        msg_bytes: &Bytes,
        // msg_st_bytes: &Bytes,
        sig_stellar: &BytesN<64>,
        sig_eth: &BytesN<65>,
    ) {
        // let msg_bytes = Bytes::from_slice(env, msg);

        match self {
            ChannelPubKey::Single(pub_key) => {
                env.crypto()
                    .ed25519_verify(pub_key, &msg_bytes, sig_stellar);
            }
            ChannelPubKey::Multi(pub_key) => {
                let recovery_id: u32 = 1;
                let msg_digest = env.crypto().keccak256(&msg_bytes);
                let mut bytes_sig_trunc = Bytes::new(&env); //from_slice(&env, &[0; 64]);
                for i in 0..64 {
                    let byte = sig_eth.get(i as u32).expect("Expected 65-byte signature");
                    bytes_sig_trunc.set(i, byte);
                }

                // let bytes: BytesN<32> = bytes.try_into().expect("bytes to have length 32");
                let sig_trunc: BytesN<64> = bytes_sig_trunc.try_into().expect("asdfadsf");
                let recovered_pub_key =
                    env.crypto()
                        .secp256k1_recover(&msg_digest, &sig_trunc, recovery_id);

                if compare_keys(&recovered_pub_key, pub_key) {
                    // Do nothing if verification is successful
                } else {
                    panic!("Public key mismatch");
                }
            }
        }
    }
}

fn compare_keys(recovered: &BytesN<65>, expected: &BytesN<65>) -> bool {
    recovered == expected
}
impl ChannelAddress {
    pub fn require_auth(&self) {
        match self {
            ChannelAddress::Single(address) => {
                address.require_auth();
            }
            ChannelAddress::Multi(address, _) => {
                address.require_auth();
            }
        }
    }

    pub fn get_address(&self) -> &Address {
        match self {
            ChannelAddress::Single(address) => {
                return &address;
            }
            ChannelAddress::Multi(address, _) => {
                return &address;
            }
        }
    }
}
