use std::str::FromStr;

use entity::LogEntry;
use ethabi::{
    ethereum_types::{H160, H256},
    Event, LogParam, RawLog,
};
// use web3::signing::keccak256;
use parity_crypto::Keccak256;
use x_com_lib::{logger::warn, status_err, x_core, Status};
pub mod bcos_api;
pub mod bcos_client_api;
pub mod entity;
pub mod utils;
pub use ethabi;
pub use hex;
mod tars_serial;

pub fn hex_addr_to_h160(address: &str) -> x_core::Result<H160> {
    let hex_addr = H160::from_str(address);
    match hex_addr {
        Ok(h16) => Ok(h16),
        Err(err) => Err(Status::error(err.to_string())),
    }
}

/**
 * 解析事件
 */
pub fn parse_event(
    raw_log: RawLog,
    event: &Event,
    prase_result: &mut Vec<(String, Vec<LogParam>)>,
) {
    let result_log = event.parse_log(raw_log);
    if result_log.is_err() {
        warn!(
            "解析 {}  事件出错: {}",
            &event.name,
            result_log.err().unwrap()
        );
        return;
    }

    let result_logs = result_log.unwrap().params;
    prase_result.push((event.name.clone(), result_logs));
}



pub fn build_raw_log(log: &LogEntry) -> RawLog {
    let logs = &log.topics;
    let mut hash_vec: Vec<H256> = Vec::with_capacity(logs.len());
    for log in logs {
        if let Ok(bytes) = hex::decode(&log[2..]) {
            if bytes.len() == 32 {
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&bytes);
                let h256 = H256(hash_array);
                hash_vec.push(h256);
            }
        }
    }
    //
    let raw_data = if log.data.len() == 0 {
        Vec::new()
    } else {
        if let Ok(bytes) = hex::decode(&log.data[2..]) {
            bytes
        } else {
            Vec::new()
        }
    };
    RawLog::from((hash_vec, raw_data))
}



pub fn labelhash(label: &str) -> [u8; 32] {
    label.as_bytes().keccak256()
}



pub fn string_to_byte32(value: &str) -> [u8; 32] {
    value.as_bytes().keccak256()
}

// pub fn dddd(laebl: &[u8:64]) -> [u8; 32] {
//     laebl.keccak256()
// }
// pub fn dsdssd(label:  &[u8;64]) -> [u8; 32] {
//     label.keccak256()
// }
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node: [u8; 32] = [0u8; 32]; // 初始为 32 字节 0
    if name.is_empty() {
        return node;
    }
    // 按照 ENS 的要求从右到左分割 label
    let labels: Vec<&str> = name.split('.').rev().collect();
    for label in labels {
        let label_hash = label.as_bytes().keccak256();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&node);
        combined[32..].copy_from_slice(&label_hash);

        node = combined.keccak256();
    }
    node
}

pub fn permission_id(
    owner_addr: &str,
    node_url: &str,
    dxc_name: &str,
    api: &str,
) -> x_core::Result<Vec<u8>> {
    let owner_addr = hex_addr_to_h160(owner_addr)?;
    let owner_addr = owner_addr.as_fixed_bytes();
    let mut input = Vec::with_capacity(20 + node_url.len() + dxc_name.len() + api.len());
    input.extend_from_slice(owner_addr);
    input.extend_from_slice(node_url.as_bytes());
    input.extend_from_slice(dxc_name.as_bytes());
    input.extend_from_slice(api.as_bytes());
    let ret = input.keccak256();
    Ok(ret.to_vec())
}

pub fn decode_permission_id(permission_id: &str) -> x_core::Result<Vec<u8>> {
    let permission_id = if permission_id.starts_with("0x") {
        &permission_id[2..]
    } else {
        &permission_id[..]
    };
    let Ok(permission_id) = hex::decode(permission_id) else {
        return status_err!("permission_id 格式不正确");
    };

    Ok(permission_id)
}




pub fn decode_revert_reason(output: &str) -> x_core::Result<String> {
    // 必须是 Error(string) 的 selector
    if !output.starts_with("0x08c379a0") {
        return status_err!("解析出错：不是 revert/require 信息");
    }
    // 去掉 "0x" 和前 4 个字节 (08c379a0)
    let data = hex::decode(&output[10..]);
    let Ok(data) = data else {
        return status_err!("解析错误信息失败：格式错误！");
    };
    // 检查长度
    if data.len() < 64 {
        return status_err!("解析错误信息失败：格式错误！");
    }

    // 取字符串长度（第 32..64 字节中的最后 4 个字节）
    let len_bytes = data[32 + 28..32 + 32].try_into();
    if let Err(_) = len_bytes {
        return status_err!("解析错误信息失败：格式错误！");
    }
    let len_bytes: [u8; 4] = len_bytes.unwrap();
    let str_len = u32::from_be_bytes(len_bytes) as usize;
    // 取字符串内容
    let str_bytes = &data[64..64 + str_len];
    let ret = String::from_utf8(str_bytes.to_vec());
    let Ok(ret) = ret else {
        return status_err!("解析错误信息失败：格式错误！");
    };
    Ok(ret)
}


pub fn status_message(status: i32) -> String {
    let msg = match status {
        0 => "成功",
        1 => "未知错误",
        10 => "错误的构造（BadInstruction）",
        11 => "跳转目标错误（BadJumpDestination）",
        12 => "Gas 不足（OutOfGas）",
        13 => "超出栈限制（OutOfStack）",
        14 => "栈下溢（StackUnderflow）",
        15 => "预编译合约执行失败（PrecompiledError）",
        16 => "交易回滚（RevertInstruction）",
        17 => "合约地址已存在（ContractAddressAlreadyUsed）",
        18 => "权限不足（PermissionDenied）",
        19 => "调用地址错误（CallAddressError）",
        21 => "合约已冻结（ContractFrozen）",
        22 => "账户已冻结（AccountFrozen）",
        23 => "账户已作废（AccountAbolished）",
        24 => "合约已废止（ContractAbolished）",
        32 => "WASM 二进制校验失败（WASMValidationFailure）",
        33 => "WASM 参数数量超限（WASMArgumentOutOfRange）",
        34 => "WASM 出现 unreachable 指令（WASMUnreachableInstruction）",
        35 => "WASM 执行失败（WASMTrap）",
        _ => "未知错误码",
    };
    msg.to_string()
}