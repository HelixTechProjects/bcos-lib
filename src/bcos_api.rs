use crate::tars_serial::{TarsOutputStream, TarsType};
use crate::utils::hex_encode_with_prefix;
use ethabi::{Function, Token};
use hyper::body::HttpBody;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Body, Client, Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use rand::{rng, Rng as _};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerName};
use rustls_pemfile::certs;
use secp256k1::{All, SecretKey};
use serde::{de::DeserializeOwned, Serialize};

use std::io::BufReader;
use std::sync::Arc;
use std::time::SystemTime;
use x_com_lib::x_core::config;
use x_com_lib::{lazy_static, x_core, Status};

use crate::entity::{
    Block, CallResult, InvokeParam, InvokeResult, Peers, Transaction, TransactionReceipt,
};
use serde_json::{Number, Value};

lazy_static! {
    static ref SECP256K1: secp256k1::Secp256k1<All> = secp256k1::Secp256k1::new();
}

struct NoVerifier {
    _root_store: RootCertStore,
}

impl NoVerifier {
    fn new(root_store: RootCertStore) -> Self {
        NoVerifier {
            _root_store: root_store,
        }
    }
}
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}



pub struct BcosApi {
    group_id: String,
    chain_id: String,
    node_id: String,
    node_url: String,
    certs: Vec<Certificate>,
    key: PrivateKey,
    no_vertifier: Arc<NoVerifier>,
}

impl BcosApi {

    
    pub(crate) fn make_private_key(private_key: &str) -> SecretKey {
        let private_key2 = if private_key.starts_with("0x") || private_key.starts_with("0X") {
            &private_key[2..]
        } else {
            &private_key
        };
        let private_key_data = hex::decode(private_key2).unwrap();

        let private_key = SecretKey::from_slice(private_key_data.as_slice()).unwrap();
        private_key
    }

    pub fn new() -> Self {
        let group_id = config::get_str("group-id").unwrap_or("group0");
        let chain_id = config::get_str("chain-id").unwrap_or("chain0");
        let node_id = config::get_str("node-id").unwrap_or("node0");
        let node_url = config::get_str("node-url").expect("缺少节点 url");

        let sdk_crt_path = config::get_str("sdk-crt-path").expect("缺少 sdk-crt");
        let sdk_key_path = config::get_str("sdk-key-path").expect("缺少 sdk-key");
        let ca_crt_path = config::get_str("ca-crt-path").expect("缺少 ca-crt");

        let certs = Self::load_certs(sdk_crt_path);
        let key = Self::load_private_key(sdk_key_path);
        let root_store = Self::load_root_ca(ca_crt_path);

        BcosApi {
            //
            certs,
            key,
            no_vertifier: Arc::new(NoVerifier::new(root_store)),
            //
            group_id: group_id.into(),
            chain_id: chain_id.into(),
            node_id: node_id.into(),
            node_url: node_url.into(),
        }
    }

    fn load_certs(path: &str) -> Vec<Certificate> {
        // 异步读取文件和转换证书
        let buf = std::fs::read(path).unwrap();
        rustls_pemfile::certs(&mut &*buf)
            .unwrap()
            .into_iter()
            .map(Certificate)
            .collect()
    }

    fn load_private_key(path: &str) -> PrivateKey {
        let buf = std::fs::read(path).unwrap();
        let keys = rustls_pemfile::pkcs8_private_keys(&mut &*buf).unwrap();
        PrivateKey(keys[0].clone())
    }

    fn load_root_ca(path: &str) -> RootCertStore {
        let file = std::fs::File::open(path).expect("cannot open CA file");
        let mut reader = BufReader::new(file);
        let certs = certs(&mut reader).expect("cannot read certs");
        let mut root_store = RootCertStore::empty();
        for cert in certs {
            root_store.add(&Certificate(cert)).unwrap();
        }
        root_store
    }

    async fn post_request<T1, T2>(
        &self,
        invoke_param: InvokeParam<T1>,
    ) -> x_core::Result<InvokeResult<T2>>
    where
        T1: Serialize,
        T2: DeserializeOwned,
    {
        let mut req = Request::builder().method(Method::POST).uri(&self.node_url);

        let headers = req.headers_mut().unwrap();

        headers.insert(
            HeaderName::from_bytes("Content-Type".as_bytes()).unwrap(),
            HeaderValue::from_str("application/json").unwrap(),
        );

        headers.insert(
            HeaderName::from_bytes("Connection".as_bytes()).unwrap(),
            HeaderValue::from_str("keep-alive").unwrap(),
        );

        let json_str = serde_json::to_string(&invoke_param).unwrap();
        let req = req.body(Body::from(json_str)).unwrap();

        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(self.no_vertifier.clone())
            .with_client_auth_cert(self.certs.clone(), self.key.clone())
            .unwrap();

        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .enable_http1() // Optionally enable HTTP/2
            .build();
        //
        let client = Client::builder().build::<_, Body>(https_connector);
        let res = client.request(req).await;
        if let Err(err) = res {
            return Err(Status::error(err.to_string()));
        }
        let mut res = res.unwrap();
        let mut all_data = Vec::new();
        loop {
            let data = res.data().await;
            if data.is_none() {
                break;
            }
            let data = data.unwrap();
            if data.is_err() {
                break;
            }
            let data = data.unwrap();
            all_data.extend_from_slice(&data);
        }

        let result = serde_json::from_slice(all_data.as_slice());
        match result {
            Ok(value) => Ok(value),
            Err(err) => Err(Status::error(err.to_string())),
        }
    }

    pub async fn call(&self, to: &str, data: String) -> x_core::Result<String> {
        let param: Vec<Value> = vec![
            serde_json::Value::String(self.group_id.clone()),
            serde_json::Value::String(self.node_id.clone()),
            serde_json::Value::String(to.into()),
            serde_json::Value::String(data),
        ];
        let invoke_param = InvokeParam::new("call".into(), param);
        let result: InvokeResult<CallResult> = self.post_request(invoke_param).await?;
        if let Some(result) = result.result {
            Ok(result.output)
        } else {
            Err(Status::error(result.error.unwrap().message))
        }
    }

    // 获取当前块高
    pub async fn get_block_number(&self) -> x_core::Result<u64> {
        let param: Vec<String> = Vec::default();
        let invoke_param = InvokeParam::new("getBlockNumber".into(), param);
        let result: InvokeResult<u64> = self.post_request(invoke_param).await?;
        if let Some(block_number) = result.result {
            Ok(block_number)
        } else {
            Err(Status::error(result.error.unwrap().message))
        }
    }

    pub async fn get_block_by_number(&self, block_number: u64) -> x_core::Result<Block> {
        let param: Vec<Value> = vec![
            serde_json::Value::String(self.group_id.clone()),
            serde_json::Value::String(self.node_id.clone()),
            serde_json::Value::Number(Number::from(block_number)),
            serde_json::Value::Bool(false),
            serde_json::Value::Bool(false),
        ];
        let invoke_param = InvokeParam::new("getBlockByNumber".into(), param);
        let result: InvokeResult<Block> = self.post_request(invoke_param).await?;
        if let Some(block_number) = result.result {
            Ok(block_number)
        } else {
            Err(Status::error(result.error.unwrap().message))
        }
    }

    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> x_core::Result<Box<TransactionReceipt>> {
        let param: Vec<Value> = vec![
            serde_json::Value::String(self.group_id.clone()),
            serde_json::Value::String(self.node_id.clone()),
            serde_json::Value::String(tx_hash.into()),
            serde_json::Value::Bool(true),
        ];

        let invoke_param = InvokeParam::new("getTransactionReceipt".into(), param);

        let result: InvokeResult<Box<TransactionReceipt>> = self.post_request(invoke_param).await?;

        if let Some(tx_receipt) = result.result {
            Ok(tx_receipt)
        } else {
            Err(Status::error(result.error.unwrap().message))
        }
    }

    pub async fn get_peers(&self) -> x_core::Result<Box<Peers>> {
        let param: Vec<String> = vec![self.group_id.clone()];

        let invoke_param = InvokeParam::new("getPeers".into(), param);

        let result: InvokeResult<Box<Peers>> = self.post_request(invoke_param).await?;

        if let Some(peers) = result.result {
            Ok(peers)
        } else {
            Err(Status::error(result.error.unwrap().message))
        }
    }

    pub async fn get_pbft_view(&self) -> x_core::Result<u64> {
        let param: Vec<String> = vec![self.group_id.clone(), self.node_id.clone()];
        let invoke_param = InvokeParam::new("getPbftView".into(), param);
        let result: InvokeResult<u64> = self.post_request(invoke_param).await?;
        if let Some(block_number) = result.result {
            Ok(block_number)
        } else {
            Err(Status::error(result.error.unwrap().message))
        }
    }

    pub fn gen_nonce() -> String {
        let mut rng = rng();
        let mut random_bytes = [0u8; 32];
        rng.fill(&mut random_bytes);
        format!("CERX{}", hex::encode(random_bytes))
    }

    pub(crate) fn encode_tx_data(
        tx: Transaction,
        hash_value: [u8; 32],
        signature_data: Vec<u8>,
        // extra_data: String,
    ) -> String {
        //
        let mut os = TarsOutputStream::new();
        //
        os.write_to_head(TarsType::StructBegin, 1);
        tx.write_to(&mut os);
        os.write_to_head(TarsType::StructEnd, 0);
        //
        os.write_bytes(&hash_value, 2);
        //
        os.write_bytes(&signature_data, 3);

        hex_encode_with_prefix(os.buf)
    }



    pub async fn send_sign_transaction(&self, sign_data: String) -> x_core::Result<String> {
        let param: Vec<Value> = vec![
            serde_json::Value::String(self.group_id.clone()),
            serde_json::Value::String(self.node_id.clone()),
            serde_json::Value::String(sign_data),
            serde_json::Value::Bool(true),
        ];
        let invoke_param = InvokeParam::new("sendTransaction".into(), param);
        let result: InvokeResult<TransactionReceipt> = self.post_request(invoke_param).await?;
        if let Some(result) = result.result {
            Ok(result.transaction_hash)
        } else {
            Err(Status::error(result.error.unwrap().message))
        }
    }



    async fn send_transaction(
        &self,
        private_key: &str,
        mut tx: Transaction,
    ) -> x_core::Result<String> {
        tx.block_limit = self.get_block_number().await? as i64 + 500;
        let sign_data = self.sign_data(private_key, tx)?;
        self.send_sign_transaction(sign_data).await
    }



    async fn send_transaction2(
        &self,
        private_key: &str,
        mut tx: Transaction,
    ) -> x_core::Result<String> {
        let private_key = Self::make_private_key(private_key);
        tx.nonce = Self::gen_nonce();
        tx.group_id = self.group_id.clone();
        tx.block_limit = self.get_block_number().await? as i64 + 500;
        tx.chain_id = self.chain_id.clone();
        let hash_value = tx.calc_tx_hash();
        let message = secp256k1::Message::from_digest_slice(&hash_value).unwrap();
        let signature = SECP256K1.sign_ecdsa_recoverable(&message, &private_key);
        let (recovery_id, compact_signature) = signature.serialize_compact();
        let mut signature_data = Vec::with_capacity(65);
        signature_data.extend_from_slice(&compact_signature);
        signature_data.push(recovery_id.to_i32() as u8);

        // let extra_data = tx.to.clone();
        let raw_tx_data = Self::encode_tx_data(tx, hash_value, signature_data);

        // info!("raw_tx_data = {}", hex::encode(&raw_tx_data));

        let param: Vec<Value> = vec![
            serde_json::Value::String(self.group_id.clone()),
            serde_json::Value::String(self.node_id.clone()),
            serde_json::Value::String(raw_tx_data),
            serde_json::Value::Bool(true),
        ];

    
        let invoke_param = InvokeParam::new("sendTransaction".into(), param);
        let result: InvokeResult<TransactionReceipt> = self.post_request(invoke_param).await?;
        if let Some(result) = result.result {
            Ok(result.transaction_hash)
        } else {
            Err(Status::error(result.error.unwrap().message))
        }
    }

    pub async fn invoke_untx_func(
        &self,
        contract_addr: &str,
        func: &Function,
        params: &[Token],
    ) -> x_core::Result<Vec<Token>> {
        let params = func.encode_input(params).unwrap();
        let call_data = format!("{}", hex::encode(&params));
        let result = self.call(contract_addr, call_data).await?;

        let result = &result.as_bytes()[2..];
        let result = hex::decode(result).unwrap();

        let output_vals = func.decode_output(&result).unwrap();
        Ok(output_vals)
    }

    pub async fn invoke_tx_func(
        &self,
        contract_addr: &str,
        private_key: &str,
        func: &Function,
        params: &[Token],
    ) -> x_core::Result<String> {
        let params: Vec<u8> = func.encode_input(params).unwrap();
        //
        let mut tx: Transaction = Transaction::default();
        tx.data = Some(params);
        tx.to = contract_addr.into();
        let tx_hash = self.send_transaction(private_key, tx).await?;
        Ok(tx_hash)
    }

    pub async fn invoke_tx_func2(
        &self,
        contract_addr: &str,
        private_key: &str,
        func: &Function,
        params: &[Token],
    ) -> x_core::Result<String> {
        let params: Vec<u8> = func.encode_input(params).unwrap();
        //
        let mut tx: Transaction = Transaction::default();
        tx.data = Some(params);
        tx.to = contract_addr.into();
        let tx_hash = self.send_transaction2(private_key, tx).await?;
        Ok(tx_hash)
    }

    pub fn sign_data(
        &self,
        private_key: &str,
        mut tx: Transaction,
    ) -> x_core::Result<String> {
        let private_key = Self::make_private_key(private_key);
        tx.nonce = Self::gen_nonce();
        tx.chain_id = self.chain_id.clone();
        tx.group_id = self.group_id.clone();
        let hash_value = tx.calc_tx_hash();
        let message = secp256k1::Message::from_digest_slice(&hash_value).unwrap();
        let signature = SECP256K1.sign_ecdsa_recoverable(&message, &private_key);
        let (recovery_id, compact_signature) = signature.serialize_compact();
        let mut signature_data = Vec::with_capacity(65);
        signature_data.extend_from_slice(&compact_signature);
        signature_data.push(recovery_id.to_i32() as u8);
        let raw_tx_data = Self::encode_tx_data(tx, hash_value, signature_data);
        Ok(raw_tx_data)
    }
}
