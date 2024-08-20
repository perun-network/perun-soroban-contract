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

use crate::multi::AddressType;
use crate::multi::ChannelAsset;
use crate::Params;
use crate::Participant;
use crate::State;
use alloy_primitives::{address, keccak256, Address, Bytes as PrimBytes, FixedBytes, U256, U64};
use alloy_sol_types::sol;
use alloy_sol_types::SolValue;
use soroban_sdk::{xdr::ToXdr, BytesN, Env};
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


    struct StateSol {
        bytes32 channelID;
        uint64 version;
        AllocationSol outcome;
        bytes appData;
        bool isFinal;
    }

    struct AssetSol {
        uint256 chainID;
        address ethHolder;
        bytes ccHolder;
    }

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

    let stellar_pubkey_xdr = participant.stellar_pubkey.clone().to_xdr(&e);
    let cc_pubkey_xdr = participant.cc_pubkey.clone().to_xdr(&e);

    let mut stellar_addr_slice = [0u8; 40];
    let mut stellar_pubkey_slice = [0u8; 104];
    let mut cc_addr_slice = [0u8; 28];
    let mut cc_pubkey_slice = [0u8; 76];

    stellar_addr_xdr.copy_into_slice(&mut stellar_addr_slice);

    stellar_pubkey_xdr.copy_into_slice(&mut stellar_pubkey_slice);

    cc_addr_xdr.copy_into_slice(&mut cc_addr_slice);

    cc_pubkey_xdr.copy_into_slice(&mut cc_pubkey_slice);

    let stellar_pubkey_alloy = PrimBytes::copy_from_slice(&stellar_pubkey_slice);
    let stellar_addr_alloy = PrimBytes::copy_from_slice(&cc_addr_slice);
    let cc_addr_alloy = Address::from_slice(&cc_addr_slice[8..28]);
    let cc_pubkey_alloy = PrimBytes::copy_from_slice(&cc_pubkey_slice[8..73]);

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

pub fn convert_allocation(e: &Env, state: &State) -> AllocationSol {
    // Ensure that there are exactly two cross-chain assets
    let cross_assets = match &state.balances.tokens {
        ChannelAsset::Cross(cross_assets) if cross_assets.len() == 2 => cross_assets,
        _ => panic!("Expected exactly two cross-chain assets"),
    };

    // Convert the first asset
    let asset_sol_0 = {
        let cross_asset = &cross_assets.get(0).unwrap();

        let chain_id = U256::from(cross_asset.chain as u8);

        let eth_holder = match cross_asset.address {
            AddressType::Eth(ref eth_address) => eth_address.clone(),
            _ => panic!("Expected Ethereum address type"),
        };

        let eth_holder_xdr = eth_holder.to_xdr(e);
        let mut eth_addr_slice = [0u8, 20];
        eth_holder_xdr.copy_into_slice(&mut eth_addr_slice);

        let eth_addr_sol = Address::from_slice(&eth_addr_slice);

        let cc_holder = match cross_asset.address {
            AddressType::Stellar(ref stellar_address) => {
                let cc_holder_xdr = stellar_address.to_xdr(e);
                let mut cc_holder_slice = [0u8; 32];
                cc_holder_xdr.copy_into_slice(&mut cc_holder_slice);
                PrimBytes::copy_from_slice(&cc_holder_slice)
            }
            _ => panic!("Expected Stellar address type"),
        };

        AssetSol {
            chainID: chain_id,
            ethHolder: eth_addr_sol,
            ccHolder: cc_holder,
        }
    };

    // Convert the second asset
    let asset_sol_1 = {
        let cross_asset = &cross_assets.get(1).unwrap();
        let chain_id = U256::from(cross_asset.chain as u8);

        let eth_holder = match cross_asset.address {
            AddressType::Eth(ref eth_address) => eth_address.clone(),
            _ => panic!("Expected Ethereum address type"),
        };

        let eth_holder_xdr = eth_holder.to_xdr(e);
        let mut eth_addr_slice = [0u8, 20];
        eth_holder_xdr.copy_into_slice(&mut eth_addr_slice);
        let eth_addr_sol = Address::from_slice(&eth_addr_slice);

        let cc_holder = match cross_asset.address {
            AddressType::Stellar(ref stellar_address) => {
                let cc_holder_xdr = stellar_address.to_xdr(e);
                let mut cc_holder_slice = [0u8; 32];
                cc_holder_xdr.copy_into_slice(&mut cc_holder_slice);
                PrimBytes::copy_from_slice(&cc_holder_slice)
            }
            _ => panic!("Expected Stellar address type"),
        };

        AssetSol {
            chainID: chain_id,
            ethHolder: eth_addr_sol,
            ccHolder: cc_holder,
        }
    };
    let bals_cc_b = U256::from(state.balances.bal_b.get(0).unwrap());
    let bals_stellar_b = U256::from(state.balances.bal_b.get(1).unwrap());
    let bals_cc_a = U256::from(state.balances.bal_a.get(0).unwrap());
    let bals_stellar_a = U256::from(state.balances.bal_a.get(1).unwrap());
    let assets_sol = [asset_sol_0, asset_sol_1].to_vec();
    let balances_sol = [
        [bals_cc_a, bals_cc_b].to_vec(),
        [bals_stellar_a, bals_stellar_b].to_vec(),
    ]
    .to_vec();

    // Construct the AllocationSol with the vectors
    AllocationSol {
        assets: assets_sol,
        balances: balances_sol,
        // locked: vec![e],
    }
}

pub fn convert_state(e: &Env, state: &State) -> StateSol {
    let channel_id_xdr = state.channel_id.clone().to_xdr(e);
    let mut channel_id_slice = [0u8, 32];
    channel_id_xdr.copy_into_slice(&mut channel_id_slice);

    let channel_id_alloy = FixedBytes::from_slice(&channel_id_slice);
    let app_data_alloy = PrimBytes::copy_from_slice(&[0u8, 32]);
    let is_final_alloy = state.finalized;

    return StateSol {
        channelID: channel_id_alloy,
        version: state.version,
        outcome: convert_allocation(e, &state),
        appData: app_data_alloy,
        isFinal: is_final_alloy,
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
