// Copyright 2025 - See NOTICE file for copyright holders.
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
use alloy_primitives::{keccak256, Address, Bytes as PrimBytes, U256};
use alloy_sol_types::sol;
use alloy_sol_types::SolValue;
use soroban_sdk::{xdr::ToXdr, BytesN, Env};

sol! {
    struct ParticipantSol {
        address ethAddress;
        bytes ccAddress;
    }

    struct ParamsSol {
        uint256 challengeDuration;
        uint256 nonce;
        ParticipantSol[] participants;
        address app;
        bool ledgerChannel;
        bool virtualChannel;
    }
    #[derive(Debug)]

    struct StateSol {
        bytes32 channelID;
        uint64 version;
        AllocationSol outcome;
        bytes appData;
        bool isFinal;
    }

    #[derive(Debug)]

    struct AssetSol {
        uint256 chainID;
        address ethHolder;
        bytes ccHolder;
    }
    #[derive(Debug)]

    struct AllocationSol {
        AssetSol[] assets;
        uint256[] backends;
        // Outer dimension are assets, inner dimension are the participants.
        uint256[][] balances;
        SubAllocSol[] locked;
    }
    #[derive(Debug)]

    struct SubAllocSol {
        // ID is the channelID of the subchannel
        bytes32[] ID; // solhint-disable-line var-name-mixedcase
        // balances holds the total balance of the subchannel of every asset.
        uint256[] balances;
        // indexMap maps each sub-channel participant to a parent channel
        // participant such that subPart[i] == parentPart[indexMap[i]].
        uint16[] indexMap;
    }

}

// convert_participant converts a Participant into a ParticipantSol
pub fn convert_participant(e: &Env, participant: &Participant) -> ParticipantSol {
    let mut stellar_addr_prefix_slice = [0u8; 36];
    stellar_addr_prefix_slice[..4].copy_from_slice(&[0, 0, 0, 0]);

    let stellar_addr_xdr = participant.stellar_addr.clone().to_xdr(&e);
    let stellar_pubkey_xdr = participant.stellar_pubkey.clone().to_array();
    let cc_addr = participant.cc_addr.clone();

    let mut cc_addr_slice = [0u8; 20];
    cc_addr.copy_into_slice(&mut cc_addr_slice);

    let cc_addr_alloy = Address::from_slice(&cc_addr_slice);
    let mut part_bytes = [0u8; 121]; // 65 + 36 + 20
    if stellar_addr_xdr.len() == 44 {
        let mut stellar_addr_slice = [0u8; 44];
        stellar_addr_xdr.copy_into_slice(&mut stellar_addr_slice);
        let stellar_addr_xdr_stripped = &stellar_addr_slice[12..];
        stellar_addr_prefix_slice[4..].copy_from_slice(stellar_addr_xdr_stripped);

        part_bytes[0..65].copy_from_slice(&stellar_pubkey_xdr); // Stellar pubkey
        part_bytes[65..101].copy_from_slice(&stellar_addr_prefix_slice); // Stellar address XDR
        part_bytes[101..121].copy_from_slice(&cc_addr_slice); // Cross-chain address
    } else if stellar_addr_xdr.len() == 40 {
        let mut stellar_addr_slice = [0u8; 40];
        stellar_addr_xdr.copy_into_slice(&mut stellar_addr_slice);
        let stellar_addr_xdr_stripped = &stellar_addr_slice[8..];
        stellar_addr_prefix_slice[4..].copy_from_slice(stellar_addr_xdr_stripped);

        part_bytes[0..65].copy_from_slice(&stellar_pubkey_xdr); // Stellar pubkey
        part_bytes[65..101].copy_from_slice(&stellar_addr_prefix_slice); // Stellar address XDR
        part_bytes[101..121].copy_from_slice(&cc_addr_slice); // Cross-chain address
    }

    let stellar_addr_alloy = PrimBytes::copy_from_slice(&part_bytes);
    return ParticipantSol {
        ethAddress: cc_addr_alloy,
        ccAddress: stellar_addr_alloy,
    };
}

// Function to convert Params to ParamsSol
pub fn convert_params(e: &Env, params: &Params) -> ParamsSol {
    // Convert participants
    let part_sol_a = convert_participant(e, &params.a);
    let part_sol_b = convert_participant(e, &params.b);
    let participants_sol = [part_sol_a, part_sol_b].to_vec();

    let nonce_bytes: [u8; 32] = params.nonce.to_array();
    let nonce_alloy = U256::from_be_bytes(nonce_bytes);
    // Challenge duration as U256
    let chall_duration = U256::from(params.challenge_duration);

    // Default app address (assuming no app is used)
    let app_alloy = Address::from_slice(&[0u8; 20]); // Null address

    ParamsSol {
        challengeDuration: chall_duration,
        nonce: nonce_alloy,
        participants: participants_sol,
        app: app_alloy,
        ledgerChannel: true,
        virtualChannel: false,
    }
}

pub fn get_channel_id_cross(e: &Env, params: &Params) -> BytesN<32> {
    let params_sol = convert_params(e, params);
    let encoded_data = params_sol.abi_encode();

    let hash = keccak256(&encoded_data);

    let hasharray = hash.into();
    let hash_bytesn = BytesN::from_array(e, &hasharray);
    return hash_bytesn;
}
