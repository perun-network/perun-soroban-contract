// Copyright 2024 - See NOTICE file for copyright holders.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![cfg(test)]
pub mod ethsig {
    use alloc::borrow::ToOwned;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{RecoveryId, Signature as k256Signature, SigningKey, VerifyingKey};
    use sha3::{Digest, Keccak256};

    pub struct EthHash(pub [u8; 32]);
    pub struct Signature(pub [u8; 65]);
    #[derive(Copy, Clone, PartialEq, Eq, Default)]
    pub struct EthAddress(pub [u8; 20]);
    pub struct EthSigner {
        skey: SigningKey,
        pubkey: VerifyingKey,
        addr: EthAddress,
    }

    impl From<&VerifyingKey> for EthAddress {
        fn from(key: &VerifyingKey) -> Self {
            // Convert the key into an EncodedPoint (on the curve), which has the
            // data we need in bytes [1..]. Then convert that into an array and
            // unwrap. This panics if the bytes representation of EncodedPoint is
            // not 65 bytes, which is unlikely to change in the dependency. If it
            // does we have bigger problems, given that its contents/layout will
            // likely change, too if the length changes.
            let pk_bytes: [u8; 65] = key.to_encoded_point(false).as_bytes().try_into().unwrap();

            // See https://ethereum.stackexchange.com/questions/65233/goethereum-getting-public-key-from-private-key-hex-formatting
            //
            // Throw away the first byte, which is not part of the public key. It is
            // added by serialize_uncompressed due to the encoding used.
            let hash: [u8; 32] = Keccak256::digest(&pk_bytes[1..]).into();

            let mut addr = EthAddress([0; 20]);
            addr.0.copy_from_slice(&hash[32 - 20..]);
            addr
        }
    }

    impl EthSigner {
        pub fn init_from_key(skey: SigningKey) -> Self {
            let addr = EthAddress::from(skey.verifying_key());
            let pubkey = skey.verifying_key().to_owned();
            Self { skey, pubkey, addr }
        }

        pub fn sign_eth(&self, msg: &EthHash) -> Signature {
            // Ethereum-style signed message hash
            let hash = hash_to_eth_signed_msg_hash(msg);

            // Use `sign_prehash()` to match old behavior (only returns `r || s`)
            let sig: k256Signature = self.skey.sign_prehash(&hash.0).unwrap();

            // Convert the signature to a 65-byte array (r || s || v)
            let mut sig_bytes: [u8; 65] = [0; 65];
            sig_bytes[..64].copy_from_slice(&sig.to_bytes());

            // We need to compute `v` manually because `sign_prehash()` does NOT return it.
            // Ethereum requires `v = rec_id + 27`, so we need to recover `rec_id`.
            let rec_id = self.compute_recovery_id(&hash.0, &sig);

            // Set Ethereum-compatible `v` value
            sig_bytes[64] = rec_id + 27;

            Signature(sig_bytes)
        }

        fn compute_recovery_id(&self, hash: &[u8; 32], sig: &k256Signature) -> u8 {
            let rec_id_0 =
                VerifyingKey::recover_from_prehash(hash, sig, RecoveryId::new(false, false));
            let rec_id_1 =
                VerifyingKey::recover_from_prehash(hash, sig, RecoveryId::new(true, false));

            match (rec_id_0, rec_id_1) {
                (Ok(pubkey_0), _) if pubkey_0 == self.pubkey => 0,
                (_, Ok(pubkey_1)) if pubkey_1 == self.pubkey => 1,
                _ => panic!("Failed to recover public key"),
            }
        }
    }

    fn hash_to_eth_signed_msg_hash(hash: &EthHash) -> EthHash {
        // Packed encoding => We can't use the serializer
        let mut hasher = Keccak256::new();
        hasher.update(b"\x19Ethereum Signed Message:\n32");
        hasher.update(hash.0);
        EthHash(hasher.finalize().into())
    }
}
