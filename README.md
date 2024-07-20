# peertlshake
Simple P2P Handshake with TLS

This example is based on a peer-to-peer connection with an Avalanche blockchain node.

### Run
```sh
cp .env.example .env

cd docker
docker compose up -d # start the node

cargo r -- 127.0.0.1:9651
```

### Optional: Generating an X.509 Key and Certificate
```sh
cargo r --example gen_x509 -- -o resources
```
