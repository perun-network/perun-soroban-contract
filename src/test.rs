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

use crate::get_channel_id;
use crate::{A, B};
use ed25519_dalek::Keypair;
use ed25519_dalek::Signer;
use rand::thread_rng;
use soroban_sdk::token::StellarAssetClient;
use soroban_sdk::xdr::{FromXdr, ToXdr};
use soroban_sdk::{token, Bytes, IntoVal};

use super::{Adjudicator, AdjudicatorClient, Balances, Params, Participant, State};
use soroban_sdk::{
    testutils::{Address as _, BytesN as _, Ledger, LedgerInfo},
    vec, Address, BytesN, Env, Vec,
};
use token::Client as TokenClient;

#[test]
fn test_signature_verification() {
    // Test if signature verifies if:
    // - participant is randomly generated by perun-stellar-backend in go
    // - participant is converted to xdr by perun-stellar-backend in go
    // - message is signed the participant's account in the perun-stellar-backend

    let env = Env::default();

    let mut bal_a = vec![&env];
    bal_a.push_back(100_i128);
    bal_a.push_back(150_i128);

    let mut bal_b = vec![&env];
    bal_b.push_back(200_i128);
    bal_b.push_back(250_i128);

    let t = setup(env, 10, bal_a, bal_b, true);
    let participant_xdr: [u8; 124] = [
        0, 0, 0, 17, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 15, 0, 0, 0, 4, 97, 100, 100, 114, 0, 0, 0,
        18, 0, 0, 0, 0, 0, 0, 0, 0, 62, 43, 159, 246, 201, 189, 121, 97, 55, 7, 106, 6, 15, 146,
        228, 22, 5, 235, 240, 191, 42, 53, 63, 107, 164, 36, 159, 171, 150, 165, 254, 45, 0, 0, 0,
        15, 0, 0, 0, 6, 112, 117, 98, 107, 101, 121, 0, 0, 0, 0, 0, 13, 0, 0, 0, 32, 201, 49, 94,
        195, 129, 245, 22, 0, 89, 205, 13, 45, 250, 131, 225, 83, 163, 190, 226, 56, 100, 194, 155,
        18, 237, 49, 107, 96, 147, 238, 142, 12,
    ];
    let participant_xdr_bytes = Bytes::from_array(&t.env, &participant_xdr);
    let msg: [u8; 4] = [116, 101, 115, 116]; // = "test"
    let msg_bytes = Bytes::from_array(&t.env, &msg);
    let sig_xdr: [u8; 64] = [
        114, 158, 1, 5, 187, 191, 244, 105, 52, 94, 148, 255, 173, 238, 65, 162, 164, 49, 165, 197,
        205, 152, 110, 253, 10, 10, 216, 32, 21, 244, 30, 77, 72, 101, 228, 203, 243, 183, 24, 94,
        249, 76, 182, 83, 192, 60, 42, 45, 107, 216, 21, 238, 24, 80, 51, 77, 192, 108, 191, 236,
        169, 159, 59, 7,
    ];
    let sig_xdr_bytes = BytesN::<64>::from_array(&t.env, &sig_xdr);
    let p = Participant::from_xdr(&t.env, &participant_xdr_bytes).unwrap();
    t.env
        .crypto()
        .ed25519_verify(&p.pubkey, &msg_bytes, &sig_xdr_bytes);
}

#[test]
fn test_honest_payment() {
    let one_withdrawer = false;

    let env = Env::default();

    // let bal_a = vec![&env, 100, 150];
    // let bal_b = vec![&env, 200, 250];

    let bal_a = vec![&env, 100, 0];
    let bal_b = vec![&env, 0, 250];

    // let bal_contract_after_afund = vec![&env, 100, 150];
    // let bal_contract_after_bfund = vec![&env, 300, 400];
    // let bal_contract_after_final = vec![&env, 300, 400];

    let bal_contract_after_afund = vec![&env, 100, 0];
    let bal_contract_after_bfund = vec![&env, 100, 250];
    let bal_contract_after_final = vec![&env, 100, 250];

    // let bal_contract_after_awdraw = vec![&env, 200, 200];
    // let bal_contract_after_bwdraw = vec![&env, 0, 0];

    let bal_contract_after_awdraw = vec![&env, 0, 200];
    let bal_contract_after_bwdraw = vec![&env, 0, 0];

    // let bal_a_after_afund = vec![&env, 0, 0];
    // let bal_a_after_awdraw = vec![&env, 100, 200];

    let bal_a_after_afund = vec![&env, 0, 0];
    let bal_a_after_awdraw = vec![&env, 100, 50];

    // let bal_b_after_bfund = vec![&env, 0, 0];
    // let bal_b_after_bwdraw = vec![&env, 200, 200];
    // let bal_a_init = vec![&env, 100, 150];
    // let bal_b_init = vec![&env, 200, 250];

    let bal_b_after_bfund = vec![&env, 0, 0];
    let bal_b_after_bwdraw = vec![&env, 0, 200];
    let bal_a_init = vec![&env, 100, 0];
    let bal_b_init = vec![&env, 0, 250];

    let to_send_a = vec![&env, 0, 50];

    // let to_send_a = vec![&env, 50, 0];

    let mut t = setup(env, 10, bal_a, bal_b, true);

    t.verify_bal_a(bal_a_init);
    t.verify_bal_b(bal_b_init);

    t.client.open(&t.params, &t.state);
    t.verify_state(&t.state);

    t.client.fund(&t.state.channel_id, &A);
    t.verify_bal_contract(bal_contract_after_afund);
    t.verify_bal_a(bal_a_after_afund);

    t.client.fund(&t.state.channel_id, &B);
    t.verify_bal_contract(bal_contract_after_bfund);
    t.verify_bal_b(bal_b_after_bfund);

    t.send_to_a(to_send_a);

    t.finalize();

    t.client.close(&t.state, &t.sig_a(), &t.sig_b());
    t.verify_state(&t.state);
    t.verify_bal_contract(bal_contract_after_final);

    t.client.withdraw(&t.state.channel_id, &A, &one_withdrawer);
    t.verify_bal_a(bal_a_after_awdraw);
    t.verify_bal_contract(bal_contract_after_awdraw);

    t.client.withdraw(&t.state.channel_id, &B, &one_withdrawer);
    t.verify_bal_b(bal_b_after_bwdraw);
    t.verify_bal_contract(bal_contract_after_bwdraw);
}

#[test]
fn test_funding_abort() {
    let env = Env::default();

    let bal_a = vec![&env, 100, 150];
    let bal_b = vec![&env, 200, 250];

    let bal_a_after_fund = vec![&env, 0, 0];
    let bal_a_after_abort = vec![&env, 100, 150];

    let bal_contract_after_afund = vec![&env, 100, 150];
    let bal_contract_after_abort = vec![&env, 0, 0];

    let t = setup(env, 10, bal_a, bal_b, true);

    t.client.open(&t.params, &t.state);
    t.verify_state(&t.state);

    t.client.fund(&t.channel_id, &A);
    t.verify_bal_contract(bal_contract_after_afund);
    t.verify_bal_a(bal_a_after_fund);

    t.client.abort_funding(&t.channel_id);
    t.verify_bal_contract(bal_contract_after_abort);
    t.verify_bal_a(bal_a_after_abort);
}

#[test]
fn test_dispute() {
    let one_withdrawer = false;

    let env = Env::default();

    let bal_a = vec![&env, 100, 150];
    let bal_b = vec![&env, 200, 250];

    let bal_contract_after_afund = vec![&env, 100, 150];
    let bal_contract_after_bfund = vec![&env, 300, 400];
    let bal_a_after_afund = vec![&env, 0, 0];
    let bal_b_after_bfund = vec![&env, 0, 0];

    let bal_a_after_wdraw = vec![&env, 100, 200];
    let bal_b_after_wdraw = vec![&env, 200, 200];

    let bal_contract_after_fclose = vec![&env, 300, 400];
    let bal_contract_after_awdraw = vec![&env, 200, 200];
    let bal_contract_after_bwdraw = vec![&env, 0, 0];

    let to_send_a = vec![&env, 0, 50];

    let mut t = setup(env, 10, bal_a, bal_b, true);
    t.client.open(&t.params, &t.state);
    t.verify_state(&t.state);

    t.client.fund(&t.state.channel_id, &A);
    t.verify_bal_contract(bal_contract_after_afund);
    t.verify_bal_a(bal_a_after_afund);

    t.client.fund(&t.state.channel_id, &B);
    t.verify_bal_contract(bal_contract_after_bfund);
    t.verify_bal_b(bal_b_after_bfund);

    t.send_to_a(to_send_a);

    t.client.dispute(&t.state, &t.sig_a(), &t.sig_b());

    t.set_ledger_time(
        t.env.ledger().get(),
        t.env.ledger().timestamp() + t.params.challenge_duration,
    );

    t.client.force_close(&t.channel_id);
    t.verify_state(&t.state);
    t.verify_bal_contract(bal_contract_after_fclose);

    t.client.withdraw(&t.channel_id, &A, &one_withdrawer);
    t.verify_bal_a(bal_a_after_wdraw);
    t.verify_bal_contract(bal_contract_after_awdraw);

    t.client.withdraw(&t.channel_id, &B, &one_withdrawer);
    t.verify_bal_b(bal_b_after_wdraw);
    t.verify_bal_contract(bal_contract_after_bwdraw);
}

#[test]
fn test_malicious_dispute() {
    let one_withdrawer = false;

    let env = Env::default();

    let bal_a = vec![&env, 100, 150];
    let bal_b = vec![&env, 200, 250];

    let bal_contract_after_afund = vec![&env, 100, 150];
    let bal_contract_after_bfund = vec![&env, 300, 400];
    let bal_contract_after_fclose = vec![&env, 300, 400];
    let bal_contract_after_awdraw = vec![&env, 150, 350];
    let bal_contract_after_bwdraw = vec![&env, 0, 0];

    let bal_a_after_afund = vec![&env, 0, 0];
    let bal_b_after_bfund = vec![&env, 0, 0];

    let bal_a_after_fwdraw = vec![&env, 150, 50];
    let bal_b_after_fwdraw = vec![&env, 150, 350];

    let to_send_bal_first = vec![&env, 50, 0];
    let to_send_bal_second = vec![&env, 0, 100];

    let mut t = setup(env, 10, bal_a, bal_b, true);
    t.client.open(&t.params, &t.state);
    t.verify_state(&t.state);

    t.client.fund(&t.state.channel_id, &A);
    t.verify_bal_contract(bal_contract_after_afund);
    t.verify_bal_a(bal_a_after_afund);

    t.client.fund(&t.state.channel_id, &B);
    t.verify_bal_contract(bal_contract_after_bfund);
    t.verify_bal_b(bal_b_after_bfund);

    t.send_to_a(to_send_bal_first);

    let (old_state, old_sig_a, old_sig_b) = t.state_and_sigs();

    t.send_to_b(to_send_bal_second);

    // malicious dispute by B (registering a state in which B still had more balance)
    t.client.dispute(&old_state, &old_sig_a, &old_sig_b);
    t.verify_state(&old_state);

    // dispute with latest state by A
    t.client.dispute(&t.state, &t.sig_a(), &t.sig_b());
    t.verify_state(&t.state);

    t.set_ledger_time(
        t.env.ledger().get(),
        t.env.ledger().timestamp() + t.params.challenge_duration,
    );

    t.client.force_close(&t.state.channel_id);
    t.verify_state(&t.state);
    t.verify_bal_contract(bal_contract_after_fclose);

    t.client.withdraw(&t.state.channel_id, &A, &one_withdrawer);
    t.verify_bal_a(bal_a_after_fwdraw);
    t.verify_bal_contract(bal_contract_after_awdraw);

    t.client.withdraw(&t.state.channel_id, &B, &one_withdrawer);
    t.verify_bal_b(bal_b_after_fwdraw);
    t.verify_bal_contract(bal_contract_after_bwdraw);
}

fn sign(e: &Env, signer: &Keypair, payload: &State) -> BytesN<64> {
    let mut heap = [0u8; 1000];
    let bytes = payload.clone().to_xdr(e);
    let len = bytes.len();
    bytes.copy_into_slice(&mut heap[..len as usize]);

    signer.sign(&heap[..len as usize]).to_bytes().into_val(e)
}

fn public_key(e: &Env, signer: &Keypair) -> BytesN<32> {
    signer.public.to_bytes().into_val(e)
}

fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

fn setup(
    e: Env,
    challenge_duration: u64,
    bal_a: Vec<i128>,
    bal_b: Vec<i128>,
    mock_auth: bool,
) -> Test<'static> {
    let ledgerinf = LedgerInfo {
        timestamp: 0,
        protocol_version: 1,
        sequence_number: 10,
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 16,
        min_persistent_entry_ttl: 4096,
        max_entry_ttl: 6312000,
    };

    e.ledger().set(ledgerinf.clone());

    if mock_auth {
        e.mock_all_auths();
    }
    let key_alice = generate_keypair();
    let key_bob = generate_keypair();
    let alice = Participant {
        addr: Address::generate(&e),
        pubkey: public_key(&e, &key_alice),
    };
    let bob = Participant {
        addr: Address::generate(&e),
        pubkey: public_key(&e, &key_bob),
    };

    if bal_a.len() != 2 {
        panic!("test setup should utilize two assets")
    }

    if bal_a.len() != bal_b.len() {
        panic!("balances arrays are not of same length");
    }

    let mut token_addresses = vec![&e];
    for i in 0..bal_a.len() {
        let admin_address = Address::generate(&e);
        let token_admin = StellarAssetClient::new(
            &e,
            &e.register_stellar_asset_contract(admin_address.clone()),
        );
        token_addresses.push_back(token_admin.address.clone());

        token_admin.mint(&alice.addr, &bal_a.get(i).unwrap());
        token_admin.mint(&bob.addr, &bal_b.get(i).unwrap());
    }

    let params = Params {
        a: alice.clone(),
        b: bob.clone(),
        nonce: BytesN::<32>::random(&e),
        challenge_duration: challenge_duration,
    };

    let channel_id = get_channel_id(&e, &params);

    let state = State {
        channel_id: channel_id.clone(),
        balances: Balances {
            tokens: token_addresses.clone(),
            bal_a: bal_a,
            bal_b: bal_b,
        },
        version: 0,
        finalized: false,
    };
    let client = AdjudicatorClient::new(&e, &e.register_contract(None, Adjudicator {}));
    Test {
        env: e,
        alice,
        bob,
        key_alice,
        key_bob,
        params,
        channel_id,
        state,
        client,
        token_addresses,
    }
}

struct Test<'a> {
    env: Env,
    alice: Participant,
    bob: Participant,
    key_alice: Keypair,
    key_bob: Keypair,
    params: Params,
    channel_id: BytesN<32>,
    state: State,
    client: AdjudicatorClient<'a>,
    token_addresses: Vec<Address>,
}

impl Test<'_> {
    fn verify_state(&self, state: &State) {
        let c = self.client.get_channel(&state.channel_id);
        assert!(c.is_some());
        assert_eq!(
            &self.client.get_channel(&state.channel_id).unwrap().state,
            state
        );
    }

    fn update(&mut self, new_state: State) {
        self.state = new_state.clone();
    }

    fn sign_state(&self, state: &State) -> (BytesN<64>, BytesN<64>) {
        let sig_a = sign(&self.env, &self.key_alice, &state);
        let sig_b = sign(&self.env, &self.key_bob, &state);
        (sig_a, sig_b)
    }

    fn send_to_a(&mut self, amt: Vec<i128>) {
        assert_eq!(
            self.state.balances.bal_a.len(),
            amt.len(),
            "length of bal_a and amt must be the same"
        );
        assert_eq!(
            self.state.balances.bal_b.len(),
            amt.len(),
            "length of bal_b and amt must be the same"
        );

        let mut new_bal_a = vec![&self.env];
        let mut new_bal_b = vec![&self.env];

        for i in 0..amt.len() {
            let bal_a = self.state.balances.bal_a.get(i).unwrap() + amt.get(i).unwrap();
            let bal_b = self.state.balances.bal_b.get(i).unwrap() - amt.get(i).unwrap();
            new_bal_a.push_back(bal_a);
            new_bal_b.push_back(bal_b);
        }

        self.update(State {
            channel_id: self.state.channel_id.clone(),
            balances: Balances {
                tokens: self.state.balances.tokens.clone(),
                bal_a: new_bal_a,
                bal_b: new_bal_b,
            },
            version: self.state.version + 1,
            finalized: self.state.finalized,
        })
    }

    fn send_to_b(&mut self, amt: Vec<i128>) {
        assert_eq!(
            self.state.balances.bal_a.len(),
            amt.len(),
            "length of bal_a and amt must be the same"
        );
        assert_eq!(
            self.state.balances.bal_b.len(),
            amt.len(),
            "length of bal_b and amt must be the same"
        );
        let mut new_bal_a = vec![&self.env];
        let mut new_bal_b = vec![&self.env];

        for i in 0..amt.len() {
            let bal_a = self.state.balances.bal_a.get(i).unwrap() - amt.get(i).unwrap();
            let bal_b = self.state.balances.bal_b.get(i).unwrap() + amt.get(i).unwrap();
            new_bal_a.push_back(bal_a);
            new_bal_b.push_back(bal_b);
        }

        self.update(State {
            channel_id: self.state.channel_id.clone(),
            balances: Balances {
                tokens: self.state.balances.tokens.clone(),
                bal_a: new_bal_a,
                bal_b: new_bal_b,
            },
            version: self.state.version + 1,
            finalized: self.state.finalized,
        })
    }

    fn finalize(&mut self) {
        self.update(State {
            version: self.state.version + 1,
            finalized: true,
            ..self.state.clone()
        })
    }

    fn sig_a(&self) -> BytesN<64> {
        sign(&self.env, &self.key_alice, &self.state)
    }

    fn sig_b(&self) -> BytesN<64> {
        sign(&self.env, &self.key_bob, &self.state)
    }

    fn sigs(&self) -> (BytesN<64>, BytesN<64>) {
        (self.sig_a(), self.sig_b())
    }

    fn gen_token_client(&self, idx: u32) -> TokenClient {
        let token_addr = self.token_addresses.get(idx).unwrap();

        let token_client = TokenClient::new(&self.env, &token_addr);
        return token_client;
    }

    fn show_bal_a(&self, idx: u32) {
        let token_client = self.gen_token_client(idx);

        panic!("Balance alice: {}", token_client.balance(&self.alice.addr),);
    }

    fn show_bal_b(&self) {
        for i in 0..self.token_addresses.len() {
            let token_client = self.gen_token_client(i);
            panic!("Balance bob: {}", token_client.balance(&self.bob.addr))
        }
    }
    fn verify_bal(&self, participant_addr: &Address, bal: Vec<i128>) {
        for i in 0..self.token_addresses.len() {
            let token_client = self.gen_token_client(i);
            assert_eq!(token_client.balance(participant_addr), bal.get(i).unwrap());
        }
    }
    fn verify_bal_a(&self, bal: Vec<i128>) {
        self.verify_bal(&self.alice.addr, bal);
    }

    fn verify_bal_contract(&self, bal: Vec<i128>) {
        for i in 0..self.token_addresses.len() {
            let token_client = self.gen_token_client(i);
            assert_eq!(
                token_client.balance(&self.client.address),
                bal.get(i).unwrap()
            );
        }
    }
    fn verify_bal_b(&self, bal: Vec<i128>) {
        self.verify_bal(&self.bob.addr, bal);
    }

    fn set_ledger_time(&mut self, params: LedgerInfo, new_time: u64) {
        self.env.ledger().set(LedgerInfo {
            timestamp: new_time,
            ..params
        });
    }

    fn state_and_sigs(&self) -> (State, BytesN<64>, BytesN<64>) {
        (self.state.clone(), self.sig_a(), self.sig_b())
    }
}
