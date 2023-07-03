#![cfg(test)]

use crate::{get_channel_id, make_channel, get_channel};

use soroban_sdk::token;

use super::{Adjudicator, AdjudicatorClient, Params, State, Control, Participant, Balances};
use soroban_sdk::{Env, testutils::{Address as _, BytesN as _}, Address, BytesN};
use token::Client as TokenClient;

#[test]
fn test() {
    let env = Env::default();
    let client = AdjudicatorClient::new(&env, &env.register_contract(None, Adjudicator{}));
    let nonce: BytesN<32> = BytesN::<32>::random(&env);
    let params = Params {
        a: Participant { addr: Address::random(&env), pubkey: BytesN::random(&env)},
        b: Participant { addr: Address::random(&env), pubkey: BytesN::random(&env)},
        nonce: nonce,
        challenge_duration: 10,
    };
    let admin = Address::random(&env);
    let token = TokenClient::new(&env, &env.register_stellar_asset_contract(admin.clone()));

    let state = State {
        channel_id: get_channel_id(&env, &params),
        balances: Balances {
            token: token.address,
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
}