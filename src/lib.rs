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
#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, token, xdr::ToXdr, Address,
    BytesN, Env, Vec,
};

mod ethsig;
mod multi;
mod sol;

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
    VerificationFailed = 22,
    InvalidPubKeyType = 23,
    InvalidKeyType = 24,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
// / Balances represent a channel state's balance distribution
pub struct Balances {
    /// token represents a channel's asset / currency. Currently this contract
    /// supports single-asset channels, but multi-asset support is possible.
    tokens: multi::ChannelAsset,
    pub bal_a: Vec<i128>,
    pub bal_b: Vec<i128>,
}

#[contracttype]
pub enum ChannelID {
    ID(BytesN<32>),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Participant {
    /// addr represents the participant's on-chain address.
    /// The participant receives payments on this address.
    pub stellar_addr: Address,
    pub cc_addr: BytesN<20>,
    /// pubkey is the participant's public key. The participant's signatures on channel
    /// states must be valid under this public key.
    pub stellar_pubkey: multi::ChannelPubKey,
    pub cc_pubkey: BytesN<65>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
/// State is the on-chain representation of a channel's state tuple.
pub struct State {
    /// channel_id is always a hash of the channel Params to which this
    /// state belongs.
    pub channel_id: BytesN<32>,
    /// balances is the balance distribution between the channel's participants
    /// in this state.
    pub balances: Balances,
    /// version is incremented on off-chain state updates and therefore establishes
    /// a strict happened-before relation between all states that belong to a channel.
    pub version: u64,
    /// finalized signals whether a state is considered final. A final state can be closed
    /// gracefully by using the `close` endpoint with both participants' signatures on the state.
    pub finalized: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Params is the on-chain version of go-perun's channel.Params.
pub struct Params {
    /// Participant A
    pub a: Participant,
    /// Participant B
    pub b: Participant,
    /// nonce ensures channel uniqueness (the nonce is generated off chain among the
    /// channel's participants).
    pub nonce: BytesN<32>,
    /// challange_duration is a duration in seconds. A channel can be force-closed, if it was disputed
    /// and the relative time lock is expired (i.e. the last dispute was at least challenge_duration
    /// seconds ago).
    pub challenge_duration: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Control contains additional information that allows
/// the contract to judge the channel's state.
pub struct Control {
    /// funded_a is true, iff A has funded the channel.
    pub funded_a: bool,
    /// funded_b is true, iff B has funded the channel.
    pub funded_b: bool,
    /// closed indicates that a fully funded channel is closed and can be withdrawn from.
    pub closed: bool,
    /// withdrawn_a is true, iff either A has already withrawn their balance from a closed channel
    /// or A's balance in the closed channel was 0 to begin with.
    pub withdrawn_a: bool,
    /// withdrawn_b is true, iff either B has already withrawn their balance from a closed channel
    /// or B's balance in the closed channel was 0 to begin with.
    pub withdrawn_b: bool,
    /// disputed is true, iff the channel was successfully disputed at least once.
    pub disputed: bool,
    /// timestamp must always contain the unix time in seconds of the last successful dispute.
    /// If the channel has not been successfully disputed, the timestamp value is not significant.
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
/// Channel is the on-chain representation of a channel.
pub struct Channel {
    /// params contains the (constant) channel parameters.
    pub params: Params,
    /// state contains the latest (on-chain) channel state.
    /// Note that there can be off-chain state updates that are more recent (have higher version number)
    /// than the registered on-chain state for a channel.
    pub state: State,
    /// control contains the channel's control bits.
    pub control: Control,
}

const A: bool = false;

const B: bool = !A;

#[contract]
pub struct Adjudicator;

#[contractimpl]
impl Adjudicator {
    /// open opens a channel in the contract instance with the given parameters
    /// and initial channel state.
    pub fn open(env: Env, params: Params, state: State) -> Result<(), Error> {
        // checks
        // We verify that the sha_256 hash of the params matches the channel id
        // in the state.
        let cid = get_channel_id(&env, &params);
        if !cid.eq(&state.channel_id) {
            return Err(Error::ChannelIDMissmatch);
        }
        // We only allow channels to be opened with initial state version number 0.
        if state.version != 0 {
            return Err(Error::InvalidVersionNumber);
        }
        // Opening channels with finalized states is pointless and thus prohibited.
        if state.finalized {
            return Err(Error::OpenOnFinalState);
        }

        if get_channel(&env, &cid).is_some() {
            return Err(Error::ChannelAlreadyExists);
        }

        // effects
        // Assemble the initial channel control struct.
        let control = Control {
            // We directly consider a channel to be funded by a party, if their balance is 0
            funded_a: false,
            funded_b: false,

            // channels are not closed, withdrawn from or disputed initially.
            closed: false,
            withdrawn_a: false,
            withdrawn_b: false,
            disputed: false,
            // We set the channel's timestamp to the current time.
            // This is not strictly required by the protocol, but it can not hurt.
            timestamp: env.ledger().timestamp(),
        };
        // Assemble the channel.
        let channel = make_channel(&params, &state, &control);
        // Write the new channel to storage.
        set_channel(&env, &channel);
        // Emit open event.
        env.events().publish(
            (symbol_short!("perun"), symbol_short!("open")),
            channel.clone(),
        );
        if is_funded(&channel) {
            env.events()
                .publish((symbol_short!("perun"), symbol_short!("fund_c")), channel);
        }

        Ok(())
    }

    /// fund funds a channel with the given channel_id. If party_idx is false, the funding
    /// is provided on behalf of party A, if party_idx is true, the funding is provided on
    /// behalf of party B.
    pub fn fund(env: Env, channel_id: BytesN<32>, party_idx: bool) -> Result<(), Error> {
        // checks
        // We get the channel with the channel id.
        let mut channel = get_channel(&env, &channel_id).ok_or(Error::ChannelNotFound)?;
        let (actor, amount) = match party_idx {
            A => {
                // Fund for party A.
                // Verify that A has not yet funded.
                if channel.control.funded_a {
                    return Err(Error::AlreadyFunded);
                }
                // Set A's funded status to true.
                // Note that the transaction is rolled back, if funding fails at a later point,
                // so doing this now is not a problem.
                channel.control.funded_a = true; // effect
                (
                    channel.params.a.stellar_addr.clone(),
                    channel.state.balances.bal_a.clone(),
                )
            }
            B => {
                // Fund for party B.
                if channel.control.funded_b {
                    return Err(Error::AlreadyFunded);
                }
                channel.control.funded_b = true; // effect
                (
                    channel.params.b.stellar_addr.clone(),
                    channel.state.balances.bal_b.clone(),
                )
            }
        };

        // effects
        // requiring auth here might not be strictly necessary, because this should
        // already be guarded by token.transfer, but again, it can not hurt.
        actor.require_auth();

        // Write the updated channel to storage.
        set_channel(&env, &channel);
        // Emit fund event.
        env.events().publish(
            (symbol_short!("perun"), symbol_short!("fund")),
            (channel.clone(), party_idx),
        );
        if is_funded(&channel) {
            env.events().publish(
                (symbol_short!("perun"), symbol_short!("fund_c")),
                channel.clone(),
            );
        }

        let contract = env.current_contract_address();
        let tokens = &channel.state.balances.tokens;

        match &tokens {
            multi::ChannelAsset::Single(address) => {
                let token_client = token::Client::new(&env, address);
                if let Some(amt) = amount.get(0) {
                    if amt > 0 {
                        token_client.transfer(&actor, &contract, &amt);
                    }
                }
            }
            multi::ChannelAsset::Multi(addresses) => {
                for (i, address) in addresses.iter().enumerate() {
                    let token_client = token::Client::new(&env, &address);
                    if let Some(amt) = amount.get(i.try_into().unwrap()) {
                        if amt > 0 {
                            token_client.transfer(&actor, &contract, &amt);
                        }
                    }
                }
            }
            multi::ChannelAsset::Cross(cross_assets) => {
                for (i, cross_asset) in cross_assets.iter().enumerate() {
                    if let multi::AddressType::Stellar(address) = &cross_asset.address {
                        let token_client = token::Client::new(&env, address);
                        if let Some(amt) = amount.get(i.try_into().unwrap()) {
                            if amt > 0 {
                                token_client.transfer(&actor, &contract, &amt);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// close gracefully closes a channel, providing a (final) signed state.
    pub fn close(
        env: Env,
        state: State,
        sig_a_stellar: BytesN<64>,
        sig_b_stellar: BytesN<64>,
        cross_chain: bool,
    ) -> Result<(), Error> {
        // checks
        // Only final states can be closed gracefully.
        if !state.finalized {
            return Err(Error::CloseOnNonFinalState);
        }
        let mut channel = get_channel(&env, &state.channel_id).ok_or(Error::ChannelNotFound)?;
        // If the channel was not funded, we prohibit closing.
        // If we would not do this, one could drain the contract's balance
        // by opening a channel, closing without funding and subsequently withdrawing.
        if !is_funded(&channel) {
            return Err(Error::OperationOnUnfundedChannel);
        }

        // We verify both parties' signatures on the submitted final state.
        let message = state.clone().to_xdr(&env);

        if cross_chain {
            channel
                .params
                .a
                .stellar_pubkey
                .verify_signature(&env, &message, &sig_a_stellar)?;
            channel
                .params
                .b
                .stellar_pubkey
                .verify_signature(&env, &message, &sig_b_stellar)?;
        } else {
            match &channel.params.a.stellar_pubkey {
                multi::ChannelPubKey::Single(pubkey) => {
                    env.crypto()
                        .ed25519_verify(pubkey, &message, &sig_a_stellar);
                }
                multi::ChannelPubKey::Cross(_) => return Err(Error::InvalidPubKeyType),
            }
            match &channel.params.b.stellar_pubkey {
                multi::ChannelPubKey::Single(pubkey) => {
                    env.crypto()
                        .ed25519_verify(pubkey, &message, &sig_b_stellar);
                }
                multi::ChannelPubKey::Cross(_) => return Err(Error::InvalidPubKeyType),
            }
        }

        // effects
        // Mark the channel as closed (to allow withdrawing).
        channel.control.closed = true;
        // Update the channel's state
        channel.state = state.clone();

        // Emit closed event.
        env.events().publish(
            (symbol_short!("perun"), symbol_short!("closed")),
            channel.clone(),
        );

        if is_withdrawn(&channel) {
            // If the channel is withdrawn at this point (both balances 0)
            // we can already delete it from contract storage and
            // emit a withdraw_complete event.
            env.events().publish(
                (symbol_short!("perun"), symbol_short!("pay_c")),
                channel.clone(),
            );
            delete_channel(&env, &channel.state.channel_id)
        } else {
            // Write the updated channel to contract storage.
            set_channel(&env, &channel);
        }

        Ok(())
    }

    /// force_close forcibly closes a channel after it has been disputed at least once and the
    /// relative timelock (challenge_duration) has elapsed since the latest dispute.
    pub fn force_close(env: Env, channel_id: BytesN<32>) -> Result<(), Error> {
        // checks
        let mut channel = get_channel(&env, &channel_id).ok_or(Error::ChannelNotFound)?;
        // We don't allow force_close on closed or unfunded channels.
        if channel.control.closed {
            return Err(Error::ForceCloseOnClosedChannel);
        }
        if !is_funded(&channel) {
            return Err(Error::OperationOnUnfundedChannel);
        }
        // The channel must have been disputed on-chain at least once.
        if !channel.control.disputed {
            return Err(Error::ForceCloseOnUndisputedChannel);
        }
        // We verify that the timelock has expired.
        if !is_timelock_expired(&env, &channel) {
            return Err(Error::TimelockNotExpired);
        }

        // effects
        // The channel is now closed, balances can be withdrawn.
        channel.control.closed = true;
        // Emit force_closed event.
        env.events().publish(
            (symbol_short!("perun"), symbol_short!("f_closed")),
            channel.clone(),
        );
        if is_withdrawn(&channel) {
            // Emit withdraw_complete event and delete the channel.
            env.events().publish(
                (symbol_short!("perun"), symbol_short!("pay_c")),
                channel.clone(),
            );
            delete_channel(&env, &channel.state.channel_id)
        } else {
            set_channel(&env, &channel);
        }

        Ok(())
    }

    /// dispute registers a given signed state on-chain. Honest parties only need to call dispute,
    /// if their peer behaves maliciously or does not respond / crashes.
    pub fn dispute(
        env: Env,
        new_state: State,
        sig_a_stellar: BytesN<64>,
        sig_b_stellar: BytesN<64>,
        cross_chain: bool,
    ) -> Result<(), Error> {
        // checks
        let mut channel = get_channel(&env, &new_state.channel_id).ok_or(Error::ChannelNotFound)?;
        // We only allow dispute on funded channels.
        if !is_funded(&channel) {
            return Err(Error::OperationOnUnfundedChannel);
        }
        // Closed channels can not be disputed.
        if channel.control.closed {
            return Err(Error::DisputeOnClosedChannel);
        }
        // We verify that the new state results from a valid state transition from the old state.
        if !is_valid_state_transition(&channel.state, &new_state) {
            return Err(Error::InvalidStateTransition);
        }

        // We verify that the new state is signed by both parties.
        let message = new_state.clone().to_xdr(&env);
        if cross_chain {
            channel
                .params
                .a
                .stellar_pubkey
                .verify_signature(&env, &message, &sig_a_stellar)?;
            channel
                .params
                .b
                .stellar_pubkey
                .verify_signature(&env, &message, &sig_b_stellar)?;
        } else {
            match &channel.params.a.stellar_pubkey {
                multi::ChannelPubKey::Single(pubkey) => {
                    env.crypto()
                        .ed25519_verify(pubkey, &message, &sig_a_stellar);
                }
                multi::ChannelPubKey::Cross(_) => return Err(Error::InvalidPubKeyType),
            }
            match &channel.params.b.stellar_pubkey {
                multi::ChannelPubKey::Single(pubkey) => {
                    env.crypto()
                        .ed25519_verify(pubkey, &message, &sig_b_stellar);
                }
                multi::ChannelPubKey::Cross(_) => return Err(Error::InvalidPubKeyType),
            }
        }

        // effects
        // We set disputed to true and update the timestamp.
        // This effectively starts the relative timelock of challenge_duration seconds.
        // If nobody disputes with a (newer) signed state in time, the channel can be force closed
        // with the current state after expiration of the timelock.
        channel.control.disputed = true;
        channel.control.timestamp = env.ledger().timestamp();
        // Set the new state and save the updated channel in the contract storage.
        channel.state = new_state;
        set_channel(&env, &channel);

        // Emit a dispute event.
        env.events().publish(
            (symbol_short!("perun"), symbol_short!("dispute")),
            channel.clone(),
        );

        Ok(())
    }

    /// withdraw is used to withdraw a party's balance from a closed channel.
    /// If the party_idx is false, withdraw is executed on behalf ob party A, else on behalf
    /// of party B.
    pub fn withdraw(env: Env, channel_id: BytesN<32>, party_idx: bool) -> Result<(), Error> {
        // checks
        let mut channel = get_channel(&env, &channel_id).ok_or(Error::ChannelNotFound)?;
        // Verify that the channel is closed.
        if !channel.control.closed {
            return Err(Error::WithdrawOnOpenChannel);
        }
        let (actor, amount) = match party_idx {
            A => {
                // We verify that A has not yet withdrawn (or 0 balance).
                if channel.control.withdrawn_a {
                    return Err(Error::AlreadyFunded);
                }
                // We mark that A has now withdrawn.
                channel.control.withdrawn_a = true; // effect
                (
                    channel.params.a.stellar_addr.clone(),
                    channel.state.balances.bal_a.clone(),
                )
            }
            B => {
                if channel.control.withdrawn_b {
                    return Err(Error::AlreadyFunded);
                }
                channel.control.withdrawn_b = true; // effect
                (
                    channel.params.b.stellar_addr.clone(),
                    channel.state.balances.bal_b.clone(),
                )
            }
        };
        actor.require_auth();

        // Emit a withdraw event with the party index.
        env.events().publish(
            (symbol_short!("perun"), symbol_short!("withdraw")),
            (channel.clone(), party_idx),
        );

        // effects
        if is_withdrawn(&channel) {
            // If the channel is withdrawn completely, emit an according event and delete it.
            env.events().publish(
                (symbol_short!("perun"), symbol_short!("pay_c")),
                channel.clone(),
            );
            delete_channel(&env, &channel_id);
        } else {
            set_channel(&env, &channel);
        }

        // interact
        let contract = env.current_contract_address();

        let tokens = &channel.state.balances.tokens;

        match &tokens {
            multi::ChannelAsset::Single(address) => {
                let token_client = token::Client::new(&env, address);
                if let Some(amt) = amount.get(0) {
                    if amt > 0 {
                        token_client.transfer(&contract, &actor, &amt);
                    }
                }
            }
            multi::ChannelAsset::Multi(addresses) => {
                for (i, address) in addresses.iter().enumerate() {
                    let token_client = token::Client::new(&env, &address);
                    if let Some(amt) = amount.get(i.try_into().unwrap()) {
                        if amt > 0 {
                            token_client.transfer(&contract, &actor, &amt);
                        }
                    }
                }
            }
            multi::ChannelAsset::Cross(cross_assets) => {
                for (i, cross_asset) in cross_assets.iter().enumerate() {
                    if let multi::AddressType::Stellar(address) = &cross_asset.address {
                        let token_client = token::Client::new(&env, address);
                        if let Some(amt) = amount.get(i.try_into().unwrap()) {
                            if amt > 0 {
                                token_client.transfer(&contract, &actor, &amt);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// abort_funding aborts a channel that has been funded by exactly one party. It is used by that
    /// party to reclaim funds, if their peer fails to fund the channel.
    pub fn abort_funding(env: Env, channel_id: BytesN<32>) -> Result<(), Error> {
        // checks
        let channel = get_channel(&env, &channel_id).ok_or(Error::ChannelNotFound)?;
        // Fully  funded channels can not be aborted.
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

        // At this point we know that exactly one party has funded the channel.
        // Now we identify that party.
        let (actor, amount) = match channel.control.funded_a {
            true => (
                channel.params.a.stellar_addr.clone(),
                channel.state.balances.bal_a.clone(),
            ),
            false => (
                channel.params.b.stellar_addr.clone(),
                channel.state.balances.bal_b.clone(),
            ),
        };
        // we don't want anyone arbitrarily aborting channels that they are not part of in
        // the channel's opening phase
        actor.require_auth();

        // effects
        // The channel is deleted from contract storage upon abort.
        delete_channel(&env, &channel_id);

        // interact
        let contract = env.current_contract_address();
        let tokens = &channel.state.balances.tokens;

        match &tokens {
            multi::ChannelAsset::Single(address) => {
                let token_client = token::Client::new(&env, address);
                if let Some(amt) = amount.get(0) {
                    if amt > 0 {
                        token_client.transfer(&contract, &actor, &amt);
                    }
                }
            }
            multi::ChannelAsset::Multi(addresses) => {
                for (i, address) in addresses.iter().enumerate() {
                    let token_client = token::Client::new(&env, &address);
                    if let Some(amt) = amount.get(i.try_into().unwrap()) {
                        if amt > 0 {
                            token_client.transfer(&contract, &actor, &amt);
                        }
                    }
                }
            }
            multi::ChannelAsset::Cross(cross_assets) => {
                for (i, cross_asset) in cross_assets.iter().enumerate() {
                    if let multi::AddressType::Stellar(address) = &cross_asset.address {
                        let token_client = token::Client::new(&env, address);
                        if let Some(amt) = amount.get(i.try_into().unwrap()) {
                            if amt > 0 {
                                token_client.transfer(&contract, &actor, &amt);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// get_channel returns the current channel with the given channel_id in the contract's
    /// channel storage.
    pub fn get_channel(env: Env, channel_id: BytesN<32>) -> Option<Channel> {
        get_channel(&env, &channel_id)
    }
}

/// get_channel returns the channel with the given id from persistent storage.
pub fn get_channel(env: &Env, id: &BytesN<32>) -> Option<Channel> {
    return env.storage().persistent().get(&ChannelID::ID(id.clone()));
}

/// set_channel writes the given channel to persistent storage.
/// The key is the channel id in the channel's state.
pub fn set_channel(env: &Env, channel: &Channel) {
    env.storage()
        .persistent()
        .set(&ChannelID::ID(channel.state.channel_id.clone()), channel);
}

/// delete_channel deletes the channel with the given id from persistent storage.
pub fn delete_channel(env: &Env, channel_id: &BytesN<32>) {
    env.storage()
        .persistent()
        .remove(&ChannelID::ID(channel_id.clone()));
}

/// get_channel_id returns the channel id for the given channel parameters.
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

/// is_valid_state_transition returns true, iff there is a valid transition from the old state
/// to the new state.
pub fn is_valid_state_transition(old: &State, new: &State) -> bool {
    // If the old state is final, there can be no "new" state.
    if old.finalized {
        return false;
    }
    // We allow the transition old state = new state, iff their version number is 0, because
    // we want to allow force-closing, if e.g. a party never responds with state updates after
    // opening and funding a channel. To allow a force close the state must be disputed first.
    if old.version == 0 && new.version == 0 {
        return old.eq(&new);
    } else if old.version >= new.version {
        // Aside from the edge-case above, the version must
        // strictly increase.
        return false;
    }
    // The state transition is only valid if they share the same channel id.
    if old.channel_id != new.channel_id {
        return false;
    }
    // Both states must have "coherent balances". That means they must:
    // a) share the same token as asset / currency
    if old.balances.tokens != new.balances.tokens {
        return false;
    }
    // // b) The sum of the balances must be equal.
    for i in 0..old.balances.bal_a.len() {
        if (old.balances.bal_a.get(i).unwrap() + old.balances.bal_b.get(i).unwrap())
            != new.balances.bal_a.get(i).unwrap() + new.balances.bal_b.get(i).unwrap()
        {
            return false;
        }
    }
    return true;
}

/// A channel is considered funded, iff both funded bits are true.
pub fn is_funded(channel: &Channel) -> bool {
    return channel.control.funded_a && channel.control.funded_b;
}

/// A channel is considered withdrawn, iff it is closed and both withdrawn bits are true.
pub fn is_withdrawn(channel: &Channel) -> bool {
    return channel.control.closed && channel.control.withdrawn_a && channel.control.withdrawn_b;
}

/// is_timelock_expired checks, if the relative timelock that (re)starts with a dispute
/// has expired. The timelock is considered to be expired, iff the channel has been disputed
/// at least once and the last dispute was at least challenge_duration seconds ago.
pub fn is_timelock_expired(env: &Env, channel: &Channel) -> bool {
    if !channel.control.disputed {
        return false;
    }
    let current_time = env.ledger().timestamp();
    return channel.control.timestamp + channel.params.challenge_duration <= current_time;
}

#[cfg(test)]
mod test;
