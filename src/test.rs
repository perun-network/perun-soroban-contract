// Copyright 2023 - See NOTICE file for copyright holders.
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

use crate::{get_channel_id};
use ed25519_dalek::Keypair;
use ed25519_dalek::Signer;
use rand::thread_rng;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{token, IntoVal};

use super::{Adjudicator, AdjudicatorClient, Balances, Params, Participant, State};
use soroban_sdk::{
    testutils::{Address as _, BytesN as _, Ledger, LedgerInfo},
    Address, BytesN, Env,
};
use token::Client as TokenClient;

#[test]
fn test_honest_payment() {
    let mut t = setup(10, 100, 200, true);
    t.client.open(&t.params, &t.state);
    t.verify_state(&t.state);

    t.client.fund(&t.state.channel_id, &false);
    t.verify_bal_contract(100);
    t.verify_bal_a(0);

    t.client.fund(&t.state.channel_id, &true);
    t.verify_bal_contract(300);
    t.verify_bal_b(0);

    t.send_to_a(100);

    t.finalize();

    t.client.close(&t.state, &t.sig_a(), &t.sig_b());
    t.verify_state(&t.state);
    t.verify_bal_contract(300);

    t.client.withdraw(&t.state.channel_id, &false);
    t.verify_bal_a(200);
    t.verify_bal_contract(100);

    t.client.withdraw(&t.state.channel_id, &true);
    t.verify_bal_b(100);
    t.verify_bal_contract(0);
}

#[test]
fn test_funding_abort() {
    let t = setup(10, 100, 200, true);

    t.client.open(&t.params, &t.state);
    t.verify_state(&t.state);

    t.client.fund(&t.channel_id, &false);
    t.verify_bal_contract(100);
    t.verify_bal_a(0);

    t.client.abort_funding(&t.channel_id);
    t.verify_bal_contract(0);
    t.verify_bal_a(100);
}

#[test]
fn test_dispute() {
    let mut t = setup(10, 100, 200, true);
    t.client.open(&t.params, &t.state);
    t.verify_state(&t.state);

    t.client.fund(&t.state.channel_id, &false);
    t.verify_bal_contract(100);
    t.verify_bal_a(0);

    t.client.fund(&t.state.channel_id, &true);
    t.verify_bal_contract(300);
    t.verify_bal_b(0);

    t.send_to_a(100);

    t.client.dispute(&t.state, &t.sig_a(), &t.sig_b());

    t.set_ledger_time(
        t.env.ledger().get(),
        t.env.ledger().timestamp() + t.params.challenge_duration,
    );

    t.client.force_close(&t.channel_id);
    t.verify_state(&t.state);
    t.verify_bal_contract(300);

    t.client.withdraw(&t.channel_id, &false);
    t.verify_bal_a(200);
    t.verify_bal_contract(100);

    t.client.withdraw(&t.channel_id, &true);
    t.verify_bal_b(100);
    t.verify_bal_contract(0);
}

#[test]
fn test_malicious_dispute() {
    let mut t = setup(10, 100, 200, true);
    t.client.open(&t.params, &t.state);
    t.verify_state(&t.state);

    t.client.fund(&t.state.channel_id, &false);
    t.verify_bal_contract(100);
    t.verify_bal_a(0);

    t.client.fund(&t.state.channel_id, &true);
    t.verify_bal_contract(300);
    t.verify_bal_b(0);

    t.send_to_a(50);

    let (old_state, old_sig_a, old_sig_b) = t.state_and_sigs();

    t.send_to_a(50);

    // malicious dispute by by B
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
    t.verify_bal_contract(300);

    t.client.withdraw(&t.state.channel_id, &false);
    t.verify_bal_a(200);
    t.verify_bal_contract(100);

    t.client.withdraw(&t.state.channel_id, &true);
    t.verify_bal_b(100);
    t.verify_bal_contract(0);
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

fn setup(challenge_duration: u64, bal_a: i128, bal_b: i128, mock_auth: bool) -> Test<'static> {
    let e = Env::default();

    let ledgerinf = LedgerInfo {
        timestamp: 0,
        protocol_version: 1,
        sequence_number: 10,
        network_id: Default::default(),
        base_reserve: 10,
    };

    e.ledger().set(ledgerinf.clone());

    if mock_auth {
        e.mock_all_auths();
    }
    let key_alice = generate_keypair();
    let key_bob = generate_keypair();
    let alice = Participant {
        addr: Address::random(&e),
        pubkey: public_key(&e, &key_alice),
    };
    let bob = Participant {
        addr: Address::random(&e),
        pubkey: public_key(&e, &key_bob),
    };
    let token = TokenClient::new(&e, &e.register_stellar_asset_contract(Address::random(&e)));
    token.mint(&alice.addr, &bal_a);
    token.mint(&bob.addr, &bal_b);
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
            token: token.address.clone(),
            bal_a: bal_a,
            bal_b: bal_b,
        },
        version: 0,
        finalized: false,
    };
    let client = AdjudicatorClient::new(&e, &e.register_contract(None, Adjudicator {}));
    Test {
        env: e,
        ledger_info: ledgerinf,
        alice,
        bob,
        key_alice,
        key_bob,
        params,
        channel_id,
        state,
        client,
        token,
    }
}

fn verify_state(t: &Test, state: &State) {
    assert_eq!(&t.client.get_channel(&state.channel_id).state, state);
}

fn sign_state(t: &Test, state: &State) -> (BytesN<64>, BytesN<64>) {
    let sig_a = sign(&t.env, &t.key_alice, &state);
    let sig_b = sign(&t.env, &t.key_bob, &state);
    (sig_a, sig_b)
}

struct Test<'a> {
    env: Env,
    ledger_info: LedgerInfo,
    alice: Participant,
    bob: Participant,
    key_alice: Keypair,
    key_bob: Keypair,
    params: Params,
    channel_id: BytesN<32>,
    state: State,
    client: AdjudicatorClient<'a>,
    token: TokenClient<'a>,
}

impl Test<'_> {
    fn verify_state(&self, state: &State) {
        assert_eq!(&self.client.get_channel(&state.channel_id).state, state);
    }

    fn update(&mut self, new_state: State) {
        self.state = new_state.clone();
    }

    fn sign_state(&self, state: &State) -> (BytesN<64>, BytesN<64>) {
        let sig_a = sign(&self.env, &self.key_alice, &state);
        let sig_b = sign(&self.env, &self.key_bob, &state);
        (sig_a, sig_b)
    }

    fn send_to_a(&mut self, amt: i128) {
        self.update(State {
            channel_id: self.state.channel_id.clone(),
            balances: Balances {
                token: self.state.balances.token.clone(),
                bal_a: self.state.balances.bal_a + amt,
                bal_b: self.state.balances.bal_b - amt,
            },
            version: self.state.version + 1,
            finalized: self.state.finalized,
        })
    }

    fn send_to_b(&mut self, amt: i128) {
        self.update(State {
            channel_id: self.state.channel_id.clone(),
            balances: Balances {
                token: self.state.balances.token.clone(),
                bal_a: self.state.balances.bal_a - amt,
                bal_b: self.state.balances.bal_b + amt,
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

    fn verify_bal_a(&self, bal: i128) {
        assert_eq!(self.token.balance(&self.alice.addr), bal);
    }

    fn verify_bal_b(&self, bal: i128) {
        assert_eq!(self.token.balance(&self.bob.addr), bal);
    }

    fn verify_bal_contract(&self, bal: i128) {
        assert_eq!(self.token.balance(&self.client.address), bal);
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
