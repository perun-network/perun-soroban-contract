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

#![no_std]
use soroban_sdk::{
    contracterror, contractimpl, contracttype, token, xdr::ToXdr, Address, BytesN, Env, Map, Symbol,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    ChannelIDMissmatch = 1,
    InvalidVersionNumber = 2,
    OpenOnFinalState = 3,
    ChannelAlreadyExists = 4,
    ChannelNotFound = 5,
    EncodingError = 6,
    InvalidActor = 7,
    AlreadyFunded = 8,
    CloseOnNonFinalState = 9,
    InvalidSignature = 10,
    OperationOnUnfundedChannel = 11,
    WithdrawOnOpenChannel = 12,
    DisputeOnClosedChannel = 13,
    InvalidStateTransition = 14,
    ForceCloseOnClosedChannel = 15,
    ForceCloseOnUndisputedChannel = 16,
    TimelockNotExpired = 17,
    AbortFundingOnFundedChannel = 18,
    AbortFundingOnClosedChannel = 19,
    AbortFundingOnDisputedChannel = 20,
    AbortFundingWithoutFunds = 21,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Balances {
    token: Address,
    pub bal_a: i128,
    pub bal_b: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Participant {
    pub addr: Address,
    pub pubkey: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub channel_id: BytesN<32>,
    pub balances: Balances,
    pub version: u64,
    pub finalized: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Params {
    pub a: Participant,
    pub b: Participant,
    pub nonce: BytesN<32>,
    pub challenge_duration: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Control {
    pub funded_a: bool,
    pub funded_b: bool,
    pub closed: bool,
    pub withdrawn_a: bool,
    pub withdrawn_b: bool,
    pub disputed: bool,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Channel {
    pub params: Params,
    pub state: State,
    pub control: Control,
}

pub struct Adjudicator;

const CHANNELS: Symbol = Symbol::short("CHANNELS");

const A: bool = false;

const B: bool = !A;

#[contractimpl]
impl Adjudicator {
    pub fn open(env: Env, params: Params, state: State) -> Result<(), Error> {
        // checks
        let cid = get_channel_id(&env, &params);
        if !cid.eq(&state.channel_id) {
            return Err(Error::ChannelIDMissmatch);
        }
        if state.version != 0 {
            return Err(Error::InvalidVersionNumber);
        }
        if state.finalized {
            return Err(Error::OpenOnFinalState);
        }

        let mut channels: Map<BytesN<32>, Channel> = env
            .storage()
            .get(&CHANNELS)
            .unwrap_or(Ok(Map::new(&env)))
            .unwrap();
        if channels.contains_key(cid.clone()) {
            return Err(Error::ChannelAlreadyExists);
        }

        // effects
        let control = Control {
            funded_a: state.balances.bal_a == 0,
            funded_b: state.balances.bal_b == 0,
            closed: false,
            withdrawn_a: false,
            withdrawn_b: false,
            disputed: false,
            timestamp: env.ledger().timestamp(),
        };
        let channel = make_channel(&params, &state, &control);
        channels.set(cid, channel.clone());
        env.storage().set(&CHANNELS, &channels);
        env.events()
            .publish((CHANNELS, Symbol::short("open")), channel);
        Ok(())
    }

    // We encode the actor index as bool. False is party A, true is party B.
    pub fn fund(env: Env, channel_id: BytesN<32>, party_idx: bool) -> Result<(), Error> {
        // checks
        let mut channel = get_channel(&env, &channel_id)?;
        let (actor, amount) = match party_idx {
            A => {  // Fund for party A.
                // Verify that A has not yet funded.
                if channel.control.funded_a {
                    return Err(Error::AlreadyFunded);
                }
                channel.control.funded_a = true; // effect
                (channel.params.a.addr.clone(), channel.state.balances.bal_a)
            }
            B => {   // Fund for party B.
                if channel.control.funded_b {
                    return Err(Error::AlreadyFunded);
                }
                channel.control.funded_b = true; // effect
                (channel.params.b.addr.clone(), channel.state.balances.bal_b)
            }
        };

        // effects
        actor.require_auth();
        set_channel(&env, &channel);

        // interact
        let contract = env.current_contract_address();
        let token_client = token::Client::new(&env, &channel.state.balances.token);
        token_client.transfer(&actor, &contract, &amount);
        Ok(())
    }

    pub fn close(
        env: Env,
        state: State,
        sig_a: BytesN<64>,
        sig_b: BytesN<64>,
    ) -> Result<(), Error> {
        // checks
        if !state.finalized {
            return Err(Error::CloseOnNonFinalState);
        }
        let mut channel = get_channel(&env, &state.channel_id)?;
        if !is_funded(&channel) {
            return Err(Error::OperationOnUnfundedChannel);
        }
        let message = state.clone().to_xdr(&env);
        env.crypto()
            .ed25519_verify(&channel.params.a.pubkey, &message, &sig_a);
        env.crypto()
            .ed25519_verify(&channel.params.b.pubkey, &message, &sig_b);

        // effects
        channel.control.closed = true;
        channel.state = state.clone();
        channel.control.withdrawn_a = state.balances.bal_a == 0;
        channel.control.withdrawn_b = state.balances.bal_b == 0;
        if is_withdrawn(&channel) {
            delete_channel(&env, &channel.state.channel_id)
        } else {
            set_channel(&env, &channel);
        }

        Ok(())
    }

    pub fn force_close(env: Env, channel_id: BytesN<32>) -> Result<(), Error> {
        // checks
        let mut channel = get_channel(&env, &channel_id)?;
        if channel.control.closed {
            return Err(Error::ForceCloseOnClosedChannel);
        }
        if !is_funded(&channel) {
            return Err(Error::OperationOnUnfundedChannel);
        }
        if !channel.control.disputed {
            return Err(Error::ForceCloseOnUndisputedChannel);
        }
        if !is_timelock_expired(&env, &channel) {
            return Err(Error::TimelockNotExpired);
        }

        // effects
        channel.control.closed = true;
        channel.control.withdrawn_a = channel.state.balances.bal_a == 0;
        channel.control.withdrawn_b = channel.state.balances.bal_b == 0;
        if is_withdrawn(&channel) {
            delete_channel(&env, &channel.state.channel_id)
        } else {
            set_channel(&env, &channel);
        }

        Ok(())
    }

    pub fn dispute(
        env: Env,
        new_state: State,
        sig_a: BytesN<64>,
        sig_b: BytesN<64>,
    ) -> Result<(), Error> {
        // checks
        let mut channel = get_channel(&env, &new_state.channel_id)?;
        if !is_funded(&channel) {
            return Err(Error::OperationOnUnfundedChannel);
        }
        if channel.control.closed {
            return Err(Error::DisputeOnClosedChannel);
        }
        if !is_valid_state_transition(&channel.state, &new_state) {
            return Err(Error::InvalidStateTransition);
        }
        let message = new_state.clone().to_xdr(&env);
        env.crypto()
            .ed25519_verify(&channel.params.a.pubkey, &message, &sig_a);
        env.crypto()
            .ed25519_verify(&channel.params.b.pubkey, &message, &sig_b);

        // effects
        channel.control.disputed = true;
        channel.control.timestamp = env.ledger().timestamp();
        channel.state = new_state;
        set_channel(&env, &channel);

        Ok(())
    }

    pub fn withdraw(env: Env, channel_id: BytesN<32>, party_idx: bool) -> Result<(), Error> {
        // checks
        let mut channel = get_channel(&env, &channel_id)?;
        if !channel.control.closed {
            return Err(Error::WithdrawOnOpenChannel);
        }
        let (actor, amount) = match party_idx {
            A => {
                // We verify that A has not yet withdrawn (or 0 balance).
                if channel.control.withdrawn_a {
                    return Err(Error::AlreadyFunded);
                }
                channel.control.withdrawn_a = true; // effect
                (channel.params.a.addr.clone(), channel.state.balances.bal_a)
            }
            B => {
                if channel.control.withdrawn_b {
                    return Err(Error::AlreadyFunded);
                }
                channel.control.withdrawn_b = true; // effect
                (channel.params.b.addr.clone(), channel.state.balances.bal_b)
            }
        };
        actor.require_auth();

        // effects
        if is_withdrawn(&channel) {
            delete_channel(&env, &channel_id);
        } else {
            set_channel(&env, &channel);
        }

        // interact
        let contract = env.current_contract_address();
        let token_client = token::Client::new(&env, &channel.state.balances.token);
        token_client.transfer(&contract, &actor, &amount);

        Ok(())
    }

    pub fn abort_funding(env: Env, channel_id: BytesN<32>) -> Result<(), Error> {
        // checks
        let channel = get_channel(&env, &channel_id)?;
        if is_funded(&channel) {
            return Err(Error::AbortFundingOnFundedChannel);
        }
        // this check is not strictly necessary but can't hurt
        if channel.control.closed {
            return Err(Error::AbortFundingOnClosedChannel);
        }
        // this check is not strictly necessary but can't hurt
        if channel.control.disputed {
            return Err(Error::AbortFundingOnDisputedChannel);
        }

        // abort makes no sense if no party has funded yet
        if !channel.control.funded_a && !channel.control.funded_b {
            return Err(Error::AbortFundingWithoutFunds);
        }

        // at this point we know that exactly one party has funded the channel
        let (actor, amount) = match channel.control.funded_a {
            true => (
                channel.params.a.addr.clone(),
                channel.state.balances.bal_a.clone(),
            ),
            false => (
                channel.params.b.addr.clone(),
                channel.state.balances.bal_b.clone(),
            ),
        };
        // we don't want anyone arbitrarily aborting channels that they are not part of in
        // the channel's opening phase
        actor.require_auth();

        // effects
        delete_channel(&env, &channel_id);

        // interact
        let contract = env.current_contract_address();
        let token_client = token::Client::new(&env, &channel.state.balances.token);
        token_client.transfer(&contract, &actor, &amount);

        Ok(())
    }

    pub fn get_channel(env: Env, channel_id: BytesN<32>) -> Result<Channel, Error> {
        get_channel(&env, &channel_id)
    }
}

// get_channel returns the channel with the given id from the environments channel map or an error if it does not exist.
pub fn get_channel(env: &Env, id: &BytesN<32>) -> Result<Channel, Error> {
    let channels: Map<BytesN<32>, Channel> = env
        .storage()
        .get(&CHANNELS)
        .unwrap_or(Ok(Map::new(&env)))
        .unwrap();
    if !channels.contains_key(id.clone()) {
        return Err(Error::ChannelNotFound);
    }
    match channels.get(id.clone()).unwrap() {
        Ok(channel) => return Ok(channel),
        Err(_) => return Err(Error::EncodingError),
    }
}

// set_channel sets the given channel in the environments channel map.
pub fn set_channel(env: &Env, channel: &Channel) {
    let mut channels: Map<BytesN<32>, Channel> = env
        .storage()
        .get(&CHANNELS)
        .unwrap_or(Ok(Map::new(&env)))
        .unwrap();
    channels.set(channel.state.channel_id.clone(), channel.clone());
    env.storage().set(&CHANNELS, &channels);
}

// delete_channel deletes the channel with the given id from the environments channel map.
pub fn delete_channel(env: &Env, channel_id: &BytesN<32>) {
    let mut channels: Map<BytesN<32>, Channel> = env
        .storage()
        .get(&CHANNELS)
        .unwrap_or(Ok(Map::new(&env)))
        .unwrap();
    channels.remove(channel_id.clone());
    env.storage().set(&CHANNELS, &channels);
}

pub fn get_channel_id(env: &Env, params: &Params) -> BytesN<32> {
    let data = params.clone().to_xdr(env);
    return env.crypto().sha256(&data);
}

pub fn make_channel(params: &Params, state: &State, control: &Control) -> Channel {
    return Channel {
        params: params.clone(),
        state: state.clone(),
        control: control.clone(),
    };
}

pub fn is_valid_state_transition(old: &State, new: &State) -> bool {
    if old.finalized {
        return false;
    }
    if old.version == 0 && new.version == 0 {
        return old.eq(&new);
    } else if old.version >= new.version {
        return false;
    }
    if old.channel_id != new.channel_id {
        return false;
    }
    if old.balances.token != new.balances.token {
        return false;
    }
    if old.balances.bal_a + old.balances.bal_b != new.balances.bal_a + new.balances.bal_b {
        return false;
    }
    return true;
}

pub fn is_funded(channel: &Channel) -> bool {
    return channel.control.funded_a && channel.control.funded_b;
}

pub fn is_withdrawn(channel: &Channel) -> bool {
    return channel.control.closed && channel.control.withdrawn_a && channel.control.withdrawn_b;
}

pub fn is_timelock_expired(env: &Env, channel: &Channel) -> bool {
    if !channel.control.disputed {
        return false;
    }
    let current_time = env.ledger().timestamp();
    return channel.control.timestamp + channel.params.challenge_duration <= current_time;
}

#[cfg(test)]
mod test;
