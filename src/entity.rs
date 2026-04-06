use crate::tars_serial::TarsOutputStream;
use byteorder::{BigEndian, WriteBytesExt};
use parity_crypto::Keccak256;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub struct InvokeParam<T> {
    pub jsonrpc: String,
    pub method: String,
    pub id: u64,
    pub params: T,
}

#[derive(Deserialize, Debug)]
pub struct InvokeResult<T> {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<T>,
    pub error: Option<InvokeError>,
}

#[derive(Deserialize, Debug)]
pub struct CallResult {
    #[serde(rename = "blockNumber")]
    pub block_number: u64,
    pub output: String,
    pub status: i32,
}

#[derive(Deserialize, Debug)]
pub struct InvokeError {
    pub code: i32,
    pub message: String,
    pub data: Option<String>,
}

impl<T> InvokeParam<T> {
    pub fn new(method: String, t: T) -> Self {
        InvokeParam {
            jsonrpc: "2.0".into(),
            method,
            id: 1,
            params: t,
        }
    }
}

#[derive(Default, Debug, Deserialize)]
pub struct GroupNodeIDInfo {
    pub group: String,

    #[serde(rename = "nodeIDList")]
    pub node_id_list: Vec<String>,
}

#[derive(Default, Debug, Deserialize)]
pub struct Peers {
    #[serde(rename = "endPoint")]
    pub end_point: String,

    #[serde(rename = "p2pNodeID")]
    pub p2p_node_id: String,

    #[serde(rename = "groupNodeIDInfo")]
    pub group_node_id_info: Vec<GroupNodeIDInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Transaction {
    //
    pub version: i32,
    #[serde(rename = "chainID")]
    pub chain_id: String,
    #[serde(rename = "groupID")]
    pub group_id: String,
    #[serde(rename = "blockLimit")]
    pub block_limit: i64,
    pub nonce: String,
    pub to: String,
    pub data: Option<Vec<u8>>,
    pub abi: String,
    #[serde(rename = "importTime")]
    pub import_time: u64,
    pub hash: String,
    pub input: String,

    pub signature: String,
}
impl Default for Transaction {
    fn default() -> Self {
        Self {
            version: 0,
            chain_id: "chain0".into(),
            group_id: "group0".into(),
            block_limit: 0,
            nonce: "0".into(),
            to: String::default(),
            data: None,
            abi: String::default(),
            import_time: 0,
            hash: String::default(),
            input: String::default(),
            signature: String::default(),
        }
    }
}

impl Transaction {
    pub fn calc_tx_hash(&self) -> [u8; 32] {
        let mut tx_data_vec = Vec::with_capacity(1024);
        // encode verison
        tx_data_vec
            .write_i32::<BigEndian>(self.version)
            .unwrap();
        // encode chain_id
        tx_data_vec.extend(self.chain_id.as_bytes());
        // encode group_id
        tx_data_vec.extend(self.group_id.as_bytes());
        // encode block_limit
        tx_data_vec
            .write_i64::<BigEndian>(self.block_limit)
            .unwrap();
        // encode nonce
        tx_data_vec.extend(self.nonce.as_bytes());
        // encode to
        tx_data_vec.extend(self.to.as_bytes());
        // encode input
        if let Some(ref data) = self.data {
            tx_data_vec.extend(data);
        }
        // tx_data_vec abi
        tx_data_vec.extend(self.abi.as_bytes());
        tx_data_vec.keccak256()
    }

    pub fn write_to(&self, os: &mut TarsOutputStream) {
        os.write_int32(self.version , 1);
        os.write_string(&self.chain_id , 2);
        os.write_string(&self.group_id , 3);
        os.write_int64(self.block_limit, 4);
        os.write_string(&self.nonce, 5);
        if !self.to.is_empty() {
            os.write_string(&self.to, 6);  
        }
        if let Some(ref data) = self.data {
            os.write_bytes(data, 7);
        } else {
            os.write_bytes(&Vec::default(), 7);  
        }
        if !self.abi.is_empty() {
            os.write_string(&self.abi, 8);  
        }
    }
}

// pub struct EncodeTransaction {
//     pub data: Transaction,
//     pub hash_value: [u8; 32],
//     pub signature_data: Vec<u8>,
//     pub import_time: i64,
//     pub attribute: i32,
//     pub sender: Vec<u8>,
//     pub extra_data: String
// }

// impl EncodeTransaction {

// }

#[derive(Debug, Deserialize, Serialize)]
pub struct LogEntry {
    pub address: String,
    pub data: String,
    pub topics: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionReceipt {
    #[serde(rename = "blockNumber")]
    pub block_number: u64,

    #[serde(rename = "checksumContractAddress")]
    pub checksum_contract_address: String,

    #[serde(rename = "contractAddress")]
    pub contract_address: String,

    #[serde(rename = "extraData")]
    pub extra_data: String,

    pub from: String,

    #[serde(rename = "gasUsed")]
    pub gas_used: String,

    pub hash: String,

    pub input: String,

    #[serde(rename = "logEntries")]
    pub log_entries: Vec<LogEntry>,

    pub message: String,
    //
    pub output: String,

    #[serde(rename = "receiptProof")]
    pub receipt_proof: Vec<String>,

    pub status: i32,

    pub to: String,

    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,

    #[serde(rename = "txReceiptProof")]
    pub tx_receipt_proof: Vec<String>,

    pub version: i32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockParentInfo {
    #[serde(rename = "blockHash")]
    pub block_hash: String,

    #[serde(rename = "blockNumber")]
    pub block_number: u64,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct Signature {
    #[serde(rename = "sealerIndex")]
    pub sealer_index: u64,

    pub signature: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct Block {
    #[serde(rename = "consensusWeights")]
    pub consensus_weights: Vec<u64>,

    #[serde(rename = "extraData")]
    pub extra_data: String,

    #[serde(rename = "gasUsed")]
    pub gas_used: String,

    pub hash: String,

    pub number: u64,

    #[serde(rename = "parentInfo")]
    pub parent_info: Vec<BlockParentInfo>,

    #[serde(rename = "receiptsRoot")]
    pub receipts_root: String,
    //
    pub sealer: u64,

    #[serde(rename = "sealerList")]
    pub sealer_list: Vec<String>,

    #[serde(rename = "signatureList")]
    pub signature_list: Vec<Signature>,

    //
    #[serde(rename = "stateRoot")]
    pub state_root: String,

    pub timestamp: u64,
    //
    pub transactions: Vec<Transaction>,

    #[serde(rename = "txsRoot")]
    pub txs_root: String,

    //
    pub version: u64,
}
