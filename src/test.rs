#![cfg(test)]


use crate::{get_channel_id, make_channel};

use ed25519_dalek::Keypair;
use ed25519_dalek::Signer;
use rand::thread_rng;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{token, IntoVal};

use super::{Adjudicator, AdjudicatorClient, Params, State, Control, Participant, Balances};
use soroban_sdk::{Env, testutils::{Address as _, BytesN as _}, Address, BytesN};
use token::Client as TokenClient;

#[test]
fn test() {
    let env = Env::default();
    env.mock_all_auths();
    let client = AdjudicatorClient::new(&env, &env.register_contract(None, Adjudicator{}));
    let nonce: BytesN<32> = BytesN::<32>::random(&env);
    let key_alice = generate_keypair();
    let key_bob = generate_keypair();
    let alice = Participant { addr: Address::random(&env), pubkey: public_key(&env, &key_alice) };
    let bob = Participant { addr: Address::random(&env), pubkey: public_key(&env, &key_bob) };
    let params = Params {
        a: alice.clone(),
        b: bob.clone(),
        nonce: nonce,
        challenge_duration: 10,
    };
    let admin = Address::random(&env);
    let token = TokenClient::new(&env, &env.register_stellar_asset_contract(admin.clone()));

    let state = State {
        channel_id: get_channel_id(&env, &params),
        balances: Balances {
            token: token.address.clone(),
            bal_a: 100,
            bal_b: 200,
        },
        version: 0,
        finalized: false,
    };
    let control = Control { funded_a: false, funded_b: false, closed: false,  withdrawn_a: false, withdrawn_b: false, disputed: false, timestamp: env.ledger().timestamp() };
    let expected = make_channel(&params, &state, &control);

    client.open(&params, &state);


    assert_eq!(
        client.get_channel(&state.channel_id), expected);

    token.mint(&alice.addr, &100i128);
    token.mint(&bob.addr, &200i128);

    client.fund(&state.channel_id, &false);

    client.fund(&state.channel_id, &true);

    let mut final_state = state.clone();
    final_state.finalized = true;
    final_state.version = 1;
    final_state.balances.bal_a = 200;
    final_state.balances.bal_b = 100;
    let sig_a = sign(&env, &key_alice, &final_state);
    let sig_b = sign(&env, &key_bob, &final_state);
    assert_eq!(token.balance(&alice.addr),0);
    assert_eq!(token.balance(&bob.addr),0);

    client.close(&final_state, &sig_a, &sig_b);
    assert_eq!(client.get_channel(&final_state.channel_id).state, final_state);
    client.withdraw(&final_state.channel_id, &false);
    assert_eq!(token.balance(&alice.addr),200i128);
    client.withdraw(&final_state.channel_id, &true);
    assert_eq!(token.balance(&bob.addr),100i128);
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