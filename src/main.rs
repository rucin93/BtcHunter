extern crate bitcoin;
extern crate secp256k1;
extern crate num_cpus;
extern crate bloom;

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
const ERROR_RATE: f32 = 0.00001;
const EXPECTED_SIZE: u32 = 50_000_000; // more than 40kk to make sure that filter is not exceeded
const DEBUG: bool = false;
const TEST: &str = "bc1q225sldtdwtjt7rm8ugedpurzujwdkt3c2xv4pt";

#[tokio::main]
async fn main() {
    println!("Starting...");

    let mut database = Vec::with_capacity(EXPECTED_SIZE as usize);
    let timer = Instant::now();

    let mut filter: BloomFilter = BloomFilter::with_rate(ERROR_RATE, EXPECTED_SIZE);

    if let Ok(lines) = read_lines(DB) {
        for line in lines {
            if let Ok(adress) = line {
                database.push(adress.to_string());
                filter.insert(&adress);
            }
        }
    }

    println!( "Load database completed in {:.2?} - size: {:?}", timer.elapsed(), database.len() );

    // test
    if filter.contains(&TEST) && database.contains(&TEST.clone().to_string()) {
        println!("Address is inside - Test passed")
    }

    let database_ = Arc::new(RwLock::new(database));
    let filter_ = Arc::new(RwLock::new(filter));
    let num_cores = num_cpus::get();

    println!("Running on {} cores", num_cores);
    
    for _ in 0..num_cores {
        let clone_database_ = Arc::clone(&database_);
        let clone_filter_ = Arc::clone(&filter_);

        task::spawn_blocking(move || {
            let current_core = std::thread::current().id();
            println!("Core {:?} started", current_core);
            let db = clone_database_.read().unwrap();
            let f = clone_filter_.read().unwrap();
            worker(&db, &f);
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
    database: &Vec<String>,
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
        println!("FOUND: {}", data.as_str())
    }
}

fn found_file_path(file: String) -> String {
  let mut path = std::env::current_dir().unwrap();
  path.push(file);
  path.to_str().unwrap().to_string()
}

fn worker(database: &Vec<String>, filter: &BloomFilter) {
  let mut count: f64 = 0.0;
  let start = Instant::now();
  loop {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let private_key = PrivateKey::new(secret_key, Network::Bitcoin);
    let public_key = key::PublicKey::from_private_key(&secp, &private_key);
    let address = Address::p2pkh(&public_key, Network::Bitcoin);

    if filter.contains(&address) {
      check_address(&private_key, secret_key, &address, database, public_key);
    }

    if DEBUG {
      count += 1.0;
      if count % 10000.0 == 0.0 {
        let current_core = std::thread::current().id();
        let elapsed = start.elapsed().as_secs_f64();
        println!( "Core {:?} hash/s: {} last address: {}", current_core, (count / elapsed).round(), &address );
      }
    }
  }
}