extern crate bitcoin;
extern crate secp256k1;
extern crate num_cpus;
extern crate bloom;

use std::collections::HashSet;
use std::fs::{OpenOptions};
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::{
    fs::File,
    io::{Write},
    time::Instant,
};

use secp256k1::{rand, Secp256k1, SecretKey};
use bitcoin::util::address::Address;
use bitcoin::util::key;
use bitcoin::{network::constants::Network, PrivateKey, PublicKey};

use bloom::{BloomFilter, ASMS};

use tokio::task;

const DB: &str = "Bitcoin_addresses_LATEST.txt";
const ERROR_RATE: f32 = 0.00001; // best for 40kk addresses
const EXPECTED_SIZE: u32 = 50_000_000; // more than 40kk to make sure that filter is not exceeded
const DEBUG: bool = true;
const TEST: &str = "bc1q225sldtdwtjt7rm8ugedpurzujwdkt3c2xv4pt";

#[tokio::main]
async fn main() {
    println!("Starting...");

    let mut database1 = HashSet::new();
    let mut database3 = HashSet::new();
    let mut databaseB = HashSet::new();
    let timer = Instant::now();

    let mut filter1: BloomFilter = BloomFilter::with_rate(ERROR_RATE, EXPECTED_SIZE / 3);
    let mut filter3: BloomFilter = BloomFilter::with_rate(ERROR_RATE, EXPECTED_SIZE / 3);
    let mut filterB: BloomFilter = BloomFilter::with_rate(ERROR_RATE, EXPECTED_SIZE / 3);

    if let Ok(lines) = read_lines(DB) {
        for line in lines {
            if let Ok(adress) = line {
                if adress.to_string().chars().nth(0) == Some('1') {
                    database1.insert(adress.to_string());
                    filter1.insert(&adress);
                } else if adress.to_string().chars().nth(0) == Some('3') {
                    database3.insert(adress.to_string());
                    filter3.insert(&adress);
                } else if adress.to_string().chars().nth(0) == Some('b') {
                    databaseB.insert(adress.to_string());
                    filterB.insert(&adress);
                }
            }
        }
    }

    println!( "Load database completed in {:.2?} ", timer.elapsed() );

    if filterB.contains(&TEST) && databaseB.contains(&TEST.clone().to_string()) {
        println!("Address is inside - Test passed")
    }

    // Multithread
    let database1_ = Arc::new(RwLock::new(database1));
    let database3_ = Arc::new(RwLock::new(database3));
    let databaseB_ = Arc::new(RwLock::new(databaseB));
    let filter1_ = Arc::new(RwLock::new(filter1));
    let filter3_ = Arc::new(RwLock::new(filter3));
    let filterB_ = Arc::new(RwLock::new(filterB));
    
    for th in 0..num_cpus::get() {
        let clone_database1_ = Arc::clone(&database1_);
        let clone_database3_ = Arc::clone(&database3_);
        let clone_databaseB_ = Arc::clone(&databaseB_);
        let clone_filter1_ = Arc::clone(&filter1_);
        let clone_filter3_ = Arc::clone(&filter3_);
        let clone_filterB_ = Arc::clone(&filterB_);
      
        task::spawn_blocking(move || {
            println!("Core {:?} started", th);
            let db1 = clone_database1_.read().unwrap();
            let db3 = clone_database3_.read().unwrap();
            let dbB = clone_databaseB_.read().unwrap();
            let f1 = clone_filter1_.read().unwrap();
            let f3 = clone_filter3_.read().unwrap();
            let fB = clone_filterB_.read().unwrap();
            
            worker(&db1, &db3, &dbB, &f1, &f3, &fB, &th);
        });
    }
}


fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn write_to_file(data: &str, file_name: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .open(file_name)
        .expect("Unable to open file");
    file.write_all(data.as_bytes()).unwrap();
}

fn check_address(
    private_key: &PrivateKey,
    secret_key: SecretKey,
    address: &Address,
    database: &HashSet<String>,
    public_key: PublicKey,
) {
    let address_string = address.to_string();
    if database.contains(&address_string) {
        let data = format!(
            "{}{}{}{}{}{}{}{}{}",
            secret_key.display_secret(),
            "\n",
            private_key.to_wif(),
            "\n",
            public_key.to_string(),
            "\n",
            address_string.as_str(),
            "\n",
            "\n",
        );
        write_to_file(data.as_str(), found_file_path("found.txt".to_string()).as_str());
        println!("{}", data.as_str())
    }
}

fn found_file_path(file: String) -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push(file);
    path.to_str().unwrap().to_string()
}

fn worker(database1: &HashSet<String>, database3: &HashSet<String>, databaseB: &HashSet<String>, filter1: &BloomFilter, filter3: &BloomFilter, filterB: &BloomFilter, th: &usize) {
    let start = Instant::now();
    let mut count: f64 = 0.0;

    loop {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let private_key = PrivateKey::new(secret_key, Network::Bitcoin);
        let public_key = key::PublicKey::from_private_key(&secp, &private_key);
        let addressP2pkh = Address::p2pkh(&public_key, Network::Bitcoin);
        let addressP2wpkh = Address::p2wpkh(&public_key, Network::Bitcoin).unwrap();
        let addressP2shwpkh = Address::p2shwpkh(&public_key, Network::Bitcoin).unwrap();

        if filter1.contains(&addressP2pkh) {
            check_address(&private_key, secret_key, &addressP2pkh, database1, public_key);
        }

        if filterB.contains(&addressP2wpkh) {
            check_address(&private_key, secret_key, &addressP2wpkh, databaseB, public_key);
        }

        if filter3.contains(&addressP2wpkh) {
            check_address(&private_key, secret_key, &addressP2wpkh, database3, public_key);
        }

        if DEBUG {
            count += 3.0;
            if count % 100000.0 == 0.0 {
                println!( "Core {:?} hash/s: {} last address: {} {} {}",
                th, (count / start.elapsed().as_secs_f64()).round(), &addressP2pkh, &addressP2wpkh, &addressP2shwpkh );
            }
        }
    }
}