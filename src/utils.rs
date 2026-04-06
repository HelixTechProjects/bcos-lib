use ethabi::{ethereum_types::U256, Token};
use parity_crypto::Keccak256;
use secp256k1::{All, PublicKey, SecretKey};
use x_com_lib::{lazy_static, status_err, x_core};

pub trait TokenConvert {
    fn to_i64(self) -> Option<i64>;
    fn to_string(self) -> Option<String>;
}

pub trait U256Convert {
    fn from_i64(value: i64) -> x_core::Result<U256>;
    fn to_i64(self) -> x_core::Result<i64>;
}

pub trait HexDecode {
    fn to_vec(&self) -> x_core::Result<Vec<u8>>;
}

pub trait HexEnCode {
    fn to_hex_string<T: AsRef<[u8]>>(data: T) -> String;
}

lazy_static! {
    static ref SECP256K1: secp256k1::Secp256k1<All> = secp256k1::Secp256k1::new();
}
pub fn public_key_to_address(public_key: &PublicKey) -> String {
    let public_key_bytes = public_key.serialize_uncompressed();
    let public_key_bytes = &public_key_bytes[1..];
    let hash = public_key_bytes.keccak256();
    let hash_hex_strng = hex::encode(hash);
    format!("0x{}", &hash_hex_strng[hash_hex_strng.len() - 40..])
}

pub fn make_private_key(private_key: &str) -> SecretKey {
    let private_key2 = if private_key.starts_with("0x") || private_key.starts_with("0X") {
        &private_key[2..]
    } else {
        &private_key
    };

    let private_key_data = hex::decode(private_key2).unwrap();
    let private_key = SecretKey::from_slice(private_key_data.as_slice()).unwrap();
    private_key
}

pub fn private_key_to_address(private_key: &str) -> String {
    let private_key = make_private_key(&private_key);
    let pk = private_key.public_key(&SECP256K1);
    return public_key_to_address(&pk);
}

pub fn hex_encode_with_prefix<T: AsRef<[u8]>>(data: T) -> String {
    format!("0x{}", hex::encode(data))
}

impl TokenConvert for Token {
    fn to_i64(self) -> Option<i64> {
        match self {
            Token::Int(n) | Token::Uint(n) => {
                if n > U256::from(i64::MAX as u64) {
                    None
                } else {
                    Some(n.low_u64() as i64)
                }
            }
            _ => None,
        }
    }

    fn to_string(self) -> Option<String> {
        match self {
            Token::Address(addr) => Some(hex_encode_with_prefix(addr)),
            Token::FixedBytes(addr) => Some(hex_encode_with_prefix(addr)),
            _ => None,
        }
    }
}

impl U256Convert for U256 {
    fn from_i64(value: i64) -> x_core::Result<U256> {
        if value < 0 {
            status_err!("的负数不能转换为 U256")
        } else {
            Ok(U256::from(value as u64))
        }
    }

    fn to_i64(self) -> x_core::Result<i64> {
        if self > U256::from(i64::MAX as u64) {
            status_err!("超出 i64 表示范围") //
        } else {
            Ok(self.low_u64() as i64)
        }
    }
}

impl HexDecode for String {
    fn to_vec(&self) -> x_core::Result<Vec<u8>> {
        let ecode_text = if self.starts_with("0x") || self.starts_with("0X") {
            &self[2..]
        } else {
            &self
        };

        let Ok(decode_bytes) = hex::decode(ecode_text) else {
            return status_err!("解析内容失败，清查输入是否正常");
        };

        Ok(decode_bytes)
    }
}
