# BTC Hunter 

Script written in Rust. 

Download dictionary - 40kk non empty BTC walets: 
```
wget 'http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz'
gzip -d Bitcoin_addresses_LATEST.txt.gz
```

Build
```
cargo rustc --release -- -C target-cpu=native
```

Run
```
./target/release/[PACKAGE NAME HERE]
```
