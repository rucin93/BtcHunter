# BTC Hunter 

This program will randomly generate bitcoin private keys, extract their bitcoin addresses and compare them with a list of addresses which have non-zero value.
Probability of finding non-zero address inside blockchain network is really low, so most probably you're wasting your energy / time.

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
./target/release/bitcoin-bruteforce
```
## Disclaimer
You're using it on your own risk. The developer shall not be, by any means, held responsible for any damage this software can cause to users of others. 
