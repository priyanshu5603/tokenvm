# VM USING HYPERSDK

Hello, this was my first experience working with HyperSDK to create virtual machines.

# Introductions

## HYPER-SDK
Introducing HyperSDK, the first framework for building high-performance Virtual Machines from scratch on Avalanche®, providing developers a foundation to build the fastest blockchains in the world, out-of-the-box.
Creating custom Virtual Machines (VMs) is one of the most powerful ways to build on Avalanche. HyperSDK is designed to simplify and accelerate custom VM development, making it safer and easier to launch your own optimized blockchain.



## Usage

The first step to running these demos is to launch your own `tokenvm` Subnet. You
can do so by running the following command from this location (may take a few
minutes):
```bash
./scripts/run.sh;
```

_By default, this allocates all funds on the network to
`token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp`. The private
key for this address is
`0x323b1d8f4eed5f0da9da93071b034f2dce9d2d22692c172f3cb252a64ddfafd01b057de320297c29ad0c1f589ea216869cf1938d88c9fbd70d6748323dbf2fa7`.
For convenience, this key has is also stored at `demo.pk`._

_If you don't need 2 Subnets for your testing, you can run `MODE="run-single"
./scripts/run.sh`._

To make it easy to interact with the `tokenvm`, we implemented the `token-cli`.
Next, you'll need to build this. You can use the following command from this location
to do so:
```bash
./scripts/build.sh
```

_This command will put the compiled CLI in `./build/token-cli`._

Lastly, you'll need to add the chains you created and the default key to the
`token-cli`. You can use the following commands from this location to do so:
```bash
./build/token-cli key import demo.pk
./build/token-cli chain import-anr
```

_`chain import-anr` connects to the Avalanche Network Runner server running in
the background and pulls the URIs of all nodes tracking each chain you
created._

### Mint and Trade
#### Step 1: Create Your Asset
First up, let's create our own asset. You can do so by running the following
command from this location:
```bash
./build/token-cli action create-asset
```

When you are done, the output should look something like this:
```
database: .token-cli
address: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp
chainID: Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9
metadata (can be changed later): MarioCoin
continue (y/n): y
✅ txID: 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
```

_`txID` is the `assetID` of your new asset._

The "loaded address" here is the address of the default private key (`demo.pk`). We
use this key to authenticate all interactions with the `tokenvm`.

#### Step 2: Mint Your Asset
After we've created our own asset, we can now mint some of it. You can do so by
running the following command from this location:
```bash
./build/token-cli action mint-asset
```

When you are done, the output should look something like this (usually easiest
just to mint to yourself).
```
database: .token-cli
address: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp
chainID: Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9
assetID: 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
metadata: MarioCoin supply: 0
recipient: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp
amount: 10000
continue (y/n): y
✅ txID: X1E5CVFgFFgniFyWcj5wweGg66TyzjK2bMWWTzFwJcwFYkF72
```

#### Step 3: View Your Balance
Now, let's check that the mint worked right by checking our balance. You can do
so by running the following command from this location:
```bash
./build/token-cli key balance
```

When you are done, the output should look something like this:
```
database: .token-cli
address: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp
chainID: Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9
assetID (use TKN for native token): 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
metadata: MarioCoin supply: 10000 warp: false
balance: 10000 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
```

#### Step 4: Create an Order
So, we have some of our token (`MarioCoin`)...now what? Let's put an order
on-chain that will allow someone to trade the native token (`TKN`) for some.
You can do so by running the following command from this location:
```bash
./build/token-cli action create-order
```

When you are done, the output should look something like this:
```
database: .token-cli
address: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp
chainID: Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9
in assetID (use TKN for native token): TKN
✔ in tick: 1█
out assetID (use TKN for native token): 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
metadata: MarioCoin supply: 10000 warp: false
balance: 10000 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
out tick: 10
supply (must be multiple of out tick): 100
continue (y/n): y
✅ txID: 2TdeT2ZsQtJhbWJuhLZ3eexuCY4UP6W7q5ZiAHMYtVfSSp1ids
```

_`txID` is the `orderID` of your new order._

The "in tick" is how much of the "in assetID" that someone must trade to get
"out tick" of the "out assetID". Any fill of this order must send a multiple of
"in tick" to be considered valid (this avoid ANY sort of precision issues with
computing decimal rates on-chain).

#### Step 5: Fill Part of the Order
Now that we have an order on-chain, let's fill it! You can do so by running the
following command from this location:
```bash
./build/token-cli action fill-order
```

When you are done, the output should look something like this:
```
database: .token-cli
address: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp
chainID: Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9
in assetID (use TKN for native token): TKN
balance: 997.999993843 TKN
out assetID (use TKN for native token): 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
metadata: MarioCoin supply: 10000 warp: false
available orders: 1
0) Rate(in/out): 100000000.0000 InTick: 1.000000000 TKN OutTick: 10 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug Remaining: 100 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
select order: 0
value (must be multiple of in tick): 2
in: 2.000000000 TKN out: 20 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
continue (y/n): y
✅ txID: uw9YrZcs4QQTEBSR3guVnzQTFyKKm5QFGVTvuGyntSTrx3aGm
```

Note how all available orders for this pair are listed by the CLI (these come
from the in-memory order book maintained by the `tokenvm`).

#### Step 6: Close Order
Let's say we now changed our mind and no longer want to allow others to fill
our order. You can cancel it by running the following command from this
location:
```bash
./build/token-cli action close-order
```

When you are done, the output should look something like this:
```
database: .token-cli
address: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp
chainID: Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9
orderID: 2TdeT2ZsQtJhbWJuhLZ3eexuCY4UP6W7q5ZiAHMYtVfSSp1ids
out assetID (use TKN for native token): 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug
continue (y/n): y
✅ txID: poGnxYiLZAruurNjugTPfN1JjwSZzGZdZnBEezp5HB98PhKcn
```

Any funds that were locked up in the order will be returned to the creator's
account.

#### Bonus: Watch Activity in Real-Time
To provide a better sense of what is actually happening on-chain, the
`index-cli` comes bundled with a simple explorer that logs all blocks/txs that
occur on-chain. You can run this utility by running the following command from
this location:
```bash
./build/token-cli chain watch
```

If you run it correctly, you'll see the following input (will run until the
network shuts down or you exit):
```
database: .token-cli
available chains: 2 excluded: []
0) chainID: Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9
1) chainID: cKVefMmNPSKmLoshR15Fzxmx52Y5yUSPqWiJsNFUg1WgNQVMX
select chainID: 0
watching for new blocks on Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9 👀
height:13 txs:1 units:488 root:2po1n8rqdpNuwpMGndqC2hjt6Xa3cUDsjEpm7D6u9kJRFEPmdL avg TPS:0.026082
✅ 2Qb172jGBtjTTLhrzYD8ZLatjg6FFmbiFSP6CBq2Xy4aBV2WxL actor: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp units: 488 summary (*actions.CreateOrder): [1.000000000 TKN -> 10 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug (supply: 50 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug)]
height:14 txs:1 units:1536 root:2vqraWhyd98zVk2ALMmbHPApXjjvHpxh4K4u1QhSb6i3w4VZxM avg TPS:0.030317
✅ 2H7wiE5MyM4JfRgoXPVP1GkrrhoSXL25iDPJ1wEiWRXkEL1CWz actor: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp units: 1536 summary (*actions.FillOrder): [2.000000000 TKN -> 20 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug (remaining: 30 27grFs9vE2YP9kwLM5hQJGLDvqEY9ii71zzdoRHNGC4Appavug)]
height:15 txs:1 units:464 root:u2FyTtup4gwPfEFybMNTgL2svvSnajfGH4QKqiJ9vpZBSvx7q avg TPS:0.036967
✅ Lsad3MZ8i5V5hrGcRxXsghV5G1o1a9XStHY3bYmg7ha7W511e actor: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp units: 464 summary (*actions.CloseOrder): [orderID: 2Qb172jGBtjTTLhrzYD8ZLatjg6FFmbiFSP6CBq2Xy4aBV2WxL]
```

### Transfer Assets to Another Subnet
Unlike the mint and trade demo, the AWM demo only requires running a single
command. You can kick off a transfer between the 2 Subnets you created by
running the following command from this location:
```bash
./build/token-cli action export
```

When you are done, the output should look something like this:
```
database: .token-cli
address: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp
chainID: Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9
✔ assetID (use TKN for native token): TKN
balance: 997.999988891 TKN
recipient: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp
amount: 10
reward: 0
available chains: 1 excluded: [Em2pZtHr7rDCzii43an2bBi1M2mTFyLN33QP1Xfjy7BcWtaH9]
0) chainID: cKVefMmNPSKmLoshR15Fzxmx52Y5yUSPqWiJsNFUg1WgNQVMX
destination: 0
swap on import (y/n): n
continue (y/n): y
✅ txID: 24Y2zR2qEQZSmyaG1BCqpZZaWMDVDtimGDYFsEkpCcWYH4dUfJ
perform import on destination (y/n): y
22u9zvTa8cRX7nork3koubETsKDn43ydaVEZZWMGcTDerucq4b to: token1rvzhmceq997zntgvravfagsks6w0ryud3rylh4cdvayry0dl97nsjzf3yp source assetID: TKN output assetID: 2rST7KDPjRvDxypr6Q4SwfAwdApLwKXuukrSc42jA3dQDgo7jx value: 10000000000 reward: 10000000000 return: false
✔ switch default chain to destination (y/n): y
```

_The `export` command will automatically run the `import` command on the
destination. If you wish to import the AWM message using a separate account,
you can run the `import` command after changing your key._

### Running a Load Test
_Before running this demo, make sure to stop the network you started using
`killall avalanche-network-runner`._

The `tokenvm` load test will provision 5 `tokenvms` and process 500k transfers
on each between 10k different accounts.

## contact

For any assistance or queries kindly write a mail to: 21021739@geu.ac.in [Priyanshu Pandey]
