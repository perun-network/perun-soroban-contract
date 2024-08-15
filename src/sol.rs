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

use crate::Params;
use crate::Participant;

use alloy_primitives::{address, keccak256, Address, Bytes as PrimBytes, U256};
use alloy_sol_types::sol;
use alloy_sol_types::SolValue;
use soroban_sdk::{xdr::ToXdr, Env};
// Define the Solidity-compatible structs using the sol! macro
sol! {
    struct ParticipantSol {
        address ccAddress;
        bytes stellarAddress;
        bytes stellarPubKey;
        bytes ccPubKey;
    }

    struct ParamsSol {
        uint256 challengeDuration;
        uint256 nonce;
        ParticipantSol[] participants;
        address app;
        bool ledgerChannel;
        bool virtualChannel;
    }
}

// Function to convert a Participant into a ParticipantSol
pub fn convert_participant(e: &Env, participant: &Participant) -> ParticipantSol {
    let stellar_addr_xdr = participant.stellar_addr.clone().to_xdr(&e);
    let cc_addr_xdr = participant.cc_addr.clone().to_xdr(&e);

    let stellar_pubkey_xdr = participant.stellar_pubkey.clone().to_xdr(&e);
    let cc_pubkey_xdr = participant.cc_pubkey.clone().to_xdr(&e);

    let mut stellar_addr_slice = [0u8, 32];
    let mut stellar_pubkey_slice = [0u8, 32];
    let mut cc_addr_slice = [0u8, 20];
    let mut cc_pubkey_slice = [0u8, 65];

    stellar_addr_xdr.copy_into_slice(&mut stellar_addr_slice);
    stellar_pubkey_xdr.copy_into_slice(&mut stellar_pubkey_slice);

    cc_addr_xdr.copy_into_slice(&mut cc_addr_slice);
    cc_pubkey_xdr.copy_into_slice(&mut cc_pubkey_slice);

    let stellar_pubkey_alloy = PrimBytes::copy_from_slice(&stellar_pubkey_slice);
    let stellar_addr_alloy = PrimBytes::copy_from_slice(&cc_addr_slice);
    let cc_addr_alloy = Address::from_slice(&cc_addr_slice);
    let cc_pubkey_alloy = PrimBytes::copy_from_slice(&cc_pubkey_slice);

    return ParticipantSol {
        ccAddress: cc_addr_alloy,
        stellarAddress: stellar_addr_alloy,
        stellarPubKey: stellar_pubkey_alloy,
        ccPubKey: cc_pubkey_alloy,
    };
}

pub fn convert_params(e: &Env, params: &Params) -> ParamsSol {
    let part_sol_a = convert_participant(e, &params.a);
    let part_sol_b = convert_participant(e, &params.b);
    let participants_sol = [part_sol_a, part_sol_b].to_vec();
    let nonce_xdr = params.nonce.clone().to_xdr(e);
    let mut nonce_slice = [0u8, 32];
    nonce_xdr.copy_into_slice(&mut nonce_slice);

    let nonce_alloy = U256::from_be_bytes(nonce_slice);
    let chall_duration = U256::from(params.challenge_duration);
    let app_alloy = address!("0000000000000000000000000000000000000000");

    return ParamsSol {
        challengeDuration: chall_duration,
        nonce: nonce_alloy,
        participants: participants_sol,
        app: app_alloy,
        ledgerChannel: true,
        virtualChannel: false,
    };
}

pub fn get_channel_id(params: &Params) -> [u8; 32] {
    let params_sol = convert_params(&Env::default(), params);
    let encoded_data = params_sol.abi_encode();

    let hash = keccak256(&encoded_data);

    hash.into()
}
