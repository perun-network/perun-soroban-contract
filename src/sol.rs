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
use alloy_primitives::{
    address, keccak256, Address as EthAddr, Address, Bytes as PrimBytes, FixedBytes, U256, U64,
};
use alloy_sol_types::sol;
use alloy_sol_types::SolValue;
use soroban_sdk::{xdr::ToXdr, BytesN, Env};

sol! {
    struct ParticipantSol {
        address ccAddress;
        bytes stellarAddress;
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
    #[derive(Debug)]

    struct StateSol {
        bytes32[] channelID;
        uint64 version;
        uint256[] backends;
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
        // Outer dimension are assets, inner dimension are the participants.
        uint256[][] balances;
        // SubAllocSol[] locked;
    }

    struct SubAllocSol {
        // ID is the channelID of the subchannel
        bytes32 ID; // solhint-disable-line var-name-mixedcase
        // balances holds the total balance of the subchannel of every asset.
        uint256[] balances;
        // indexMap maps each sub-channel participant to a parent channel
        // participant such that subPart[i] == parentPart[indexMap[i]].
        uint16[] indexMap;
    }

}

// Function to convert a Participant into a ParticipantSol
pub fn convert_participant(e: &Env, participant: &Participant) -> ParticipantSol {
    let stellar_addr_xdr = participant.stellar_addr.clone().to_xdr(&e);
    let cc_addr_xdr = participant.cc_addr.clone().to_xdr(&e);

    let cc_pubkey_xdr = participant.stellar_pubkey.clone().to_xdr(&e);

    let mut stellar_addr_slice = [0u8; 40];
    let mut cc_addr_slice = [0u8; 28];
    let mut cc_pubkey_slice = [0u8; 104];

    stellar_addr_xdr.copy_into_slice(&mut stellar_addr_slice);

    cc_addr_xdr.copy_into_slice(&mut cc_addr_slice);

    cc_pubkey_xdr.copy_into_slice(&mut cc_pubkey_slice);

    let cc_pubkey_alloy = PrimBytes::copy_from_slice(&cc_pubkey_slice);

    let stellar_addr_alloy = PrimBytes::copy_from_slice(&cc_addr_slice);
    let cc_addr_alloy = Address::from_slice(&cc_addr_slice[8..28]);

    return ParticipantSol {
        ccAddress: cc_addr_alloy,
        stellarAddress: stellar_addr_alloy,
        ccPubKey: cc_pubkey_alloy,
    };
}

pub fn convert_params(e: &Env, params: &Params) -> ParamsSol {
    let part_sol_a = convert_participant(e, &params.a);
    let part_sol_b = convert_participant(e, &params.b);
    let participants_sol = [part_sol_a, part_sol_b].to_vec();

    let nonce_xdr = params.nonce.clone().to_xdr(e);
    let mut nonce_slice = [0u8; 40];

    nonce_xdr.copy_into_slice(&mut nonce_slice);
    let nonce_array: [u8; 32] = nonce_slice[8..40]
        .try_into()
        .expect("Slice with incorrect length");
    let nonce_alloy = U256::from_be_bytes(nonce_array);
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

pub fn get_channel_id_cross(e: &Env, params: &Params) -> BytesN<32> {
    let params_sol = convert_params(e, params);
    let encoded_data = params_sol.abi_encode();

    let hash = keccak256(&encoded_data);

    let hasharray = hash.into();
    let hash_bytesn = BytesN::from_array(e, &hasharray);
    return hash_bytesn;
}
