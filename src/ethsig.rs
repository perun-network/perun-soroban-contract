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
    pub use k256::ecdsa::Error;
    use k256::{
        ecdsa::{
            recoverable,
            signature::{hazmat::PrehashSigner, Signature as k256Signature},
            SigningKey, VerifyingKey,
        },
        elliptic_curve::sec1::ToEncodedPoint,
    };
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

    impl From<VerifyingKey> for EthAddress {
        fn from(key: VerifyingKey) -> Self {
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
        pub fn new<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
            let skey = SigningKey::random(rng);
            let addr = skey.verifying_key().into();
            let pubkey = skey.verifying_key();
            Self { skey, pubkey, addr }
        }

        pub fn init_from_key(skey: SigningKey) -> Self {
            let addr = skey.verifying_key().into();
            let pubkey = skey.verifying_key();
            Self { skey, pubkey, addr }
        }

        pub fn get_key(&self) -> &SigningKey {
            &self.skey
        }

        pub fn address(&self) -> EthAddress {
            self.addr
        }

        pub fn verifying_key(&self) -> VerifyingKey {
            self.pubkey
        }

        pub fn sign_eth(&self, msg: &EthHash) -> Signature {
            //actually it is BytesN<65>, but we omit the last one, for rec =1 sign for Ethereum-type addresses
            // "\x19Ethereum Signed Message:\n32" format
            let hash = hash_to_eth_signed_msg_hash(msg);

            let sig: recoverable::Signature = self.skey.sign_prehash(&hash.0).unwrap();

            // Luckily for us, this Signature type already has the format we need:
            // - 65 bytes containing r, s and v in this order
            //
            // But we still have to add 27 to v for the signature to be valid in the
            // EVM.
            let mut sig_bytes: [u8; 65] = sig.as_bytes().try_into().expect(
                "Unreachable: Signature size doesn't match, something big must have changed in the dependency",
            );
            debug_assert!(sig_bytes[32] & 0x80 == 0);
            sig_bytes[64] += 27;

            Signature(sig_bytes)
        }

        pub fn recover_address(
            &self,
            msg: EthHash,
            eth_sig: Signature,
        ) -> Result<EthAddress, Error> {
            let hash = hash_to_eth_signed_msg_hash(&msg);

            // Undo adding the 27, to go back to the format expected below
            let mut sig_bytes: [u8; 65] = eth_sig.0;
            sig_bytes[64] -= 27;

            let sig = recoverable::Signature::from_bytes(&sig_bytes)
                .expect("Can't fail because size is known at compile time");

            let verifying_key = sig.recover_verifying_key_from_digest_bytes(&hash.0.into())?;
            Ok(verifying_key.into())
        }

        pub fn recover_signer(
            &self,
            msg: EthHash,
            eth_sig: Signature,
        ) -> Result<VerifyingKey, Error> {
            // "\x19Ethereum Signed Message:\n32" format
            let hash = hash_to_eth_signed_msg_hash(&msg);

            // Undo adding the 27, to go back to the format expected below
            let mut sig_bytes: [u8; 65] = eth_sig.0;
            sig_bytes[64] -= 27;

            let sig = recoverable::Signature::from_bytes(&sig_bytes)
                .expect("Can't fail because size is known at compile time");

            let verifying_key = sig.recover_verifying_key_from_digest_bytes(&hash.0.into())?;
            Ok(verifying_key.into())
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
