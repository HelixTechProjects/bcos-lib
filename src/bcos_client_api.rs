use secp256k1::All;
use x_com_lib::{
    lazy_static,
    x_core::{self, config},
};

use crate::{bcos_api::BcosApi, entity::Transaction};

lazy_static! {
    static ref SECP256K1: secp256k1::Secp256k1<All> = secp256k1::Secp256k1::new();
}

pub struct BcosClientApi {
    group_id: String,
    chain_id: String,
}

impl BcosClientApi {
    //
    pub fn new() -> Self {
        let group_id = config::get_str("group-id").unwrap_or("group0");
        let chain_id = config::get_str("chain-id").unwrap_or("chain0");

        BcosClientApi {
            group_id: group_id.into(),
            chain_id: chain_id.into(),
        }
    }

    pub fn sign_data(
        &self,
        private_key: &str,
        mut tx: Transaction,
    ) -> x_core::Result<String> {
        let private_key = BcosApi::make_private_key(private_key);
        tx.nonce = BcosApi::gen_nonce();
        tx.chain_id = self.chain_id.clone();
        tx.group_id = self.group_id.clone();
        let hash_value = tx.calc_tx_hash();
        let message = secp256k1::Message::from_digest_slice(&hash_value).unwrap();
        let signature = SECP256K1.sign_ecdsa_recoverable(&message, &private_key);
        let (recovery_id, compact_signature) = signature.serialize_compact();
        let mut signature_data = Vec::with_capacity(65);
        signature_data.extend_from_slice(&compact_signature);
        signature_data.push(recovery_id.to_i32() as u8);
        let raw_tx_data = BcosApi::encode_tx_data(tx, hash_value, signature_data);
        Ok(raw_tx_data)
    }
}
