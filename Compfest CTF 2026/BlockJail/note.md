# BlockJail — Compfest CTF 2026

This is a beginner-friendly writeup for the **BlockJail** blockchain challenge. It assumes only a basic understanding of Ethereum transactions and Solidity.

## Flag

```text
COMPFEST18{I_guess_bro_here_is_relatively_secure_mirror_flag_you_have_searched_for_0f95fd47}
```

## 1. What are we trying to do?

The challenge gives us a temporary blockchain instance. `Setup.sol` deploys the contracts and provides an `isSolved()` function. We win when all three conditions below are true:

```solidity
TARGET.pathOpened() == true
TARGET.balance == 0
PalaceVault(PALACE).isSolved() == true
```

In plain English:

1. Open the path inside `BlockJail`.
2. Remove all ETH from `BlockJail`.
3. Complete the puzzle inside `PalaceVault`.

The supplied files are [BlockJail.sol](./BlockJail.sol), [Setup.sol](./Setup.sol), and [foundry.toml](./foundry.toml). `PalaceVault.sol` was not included, so that contract had to be investigated through its deployed bytecode and public functions.

### The predicted `BlockJail` address

`Setup` creates two contracts in its constructor. The first one is `PalaceVault`, and the second one is `BlockJail`. Ethereum contract creation uses a nonce that starts at 1, so `BlockJail` is created with nonce 2.

`Setup` calculates the address that should result from creating a contract from `Setup` with nonce 2, then checks that the actual `BlockJail` address matches it. This is why the forwarding implementation can know the `BlockJail` address ahead of time and embed it in its bytecode. In a real solve, read `TARGET()` from `Setup` or reproduce the same calculation before constructing the implementation.

## 2. A few Ethereum ideas first

### Externally owned accounts and contracts

An Ethereum address can belong to either:

- an **EOA**, which is controlled by a private key; or
- a **contract**, which contains EVM bytecode.

The challenge does not allow our wallet to register directly as the agent. We must deploy a contract whose bytecode passes a strict validator.

### `msg.sender` and `tx.origin`

For a transaction such as:

```text
our wallet -> Agent -> BlockJail
```

the values are different at each call:

- `tx.origin` is still our wallet for the whole transaction;
- `msg.sender` is the contract that made the current call.

`BlockJail.enter()` records `tx.origin` as the beneficiary. This means that after the agent is accepted, `stealHeart()` sends the ETH to our wallet.

### `CALL` versus `DELEGATECALL`

These two EVM instructions are important here:

- `CALL` runs another contract and makes that contract see the caller as `msg.sender`.
- `DELEGATECALL` runs another contract's code while keeping the caller's storage, address, and call context.

Our final call path is:

```text
wallet -> Agent -> BlockJail -> PalaceVault
```

The agent uses `DELEGATECALL` to run a tiny forwarding implementation, and that implementation uses `CALL` to call `BlockJail`. Therefore `BlockJail` sees the approved agent as `msg.sender`.

## 3. Reading the `BlockJail` restrictions

The important part of `enter()` is:

```solidity
function enter() external {
    if (agent != address(0) || msg.sender.code.length == 0) revert InvalidAgent();
    _validateAgentRuntime(msg.sender);
    agent = msg.sender;
    beneficiary = tx.origin;
}
```

This tells us three things:

1. We can register only once.
2. The caller must be a contract, not a wallet.
3. The contract's **runtime bytecode** must pass `_validateAgentRuntime()`.

The validator requires the agent bytecode to:

- be no longer than 36 bytes;
- contain exactly one `DELEGATECALL` (`0xf4`);
- use only the allowed opcodes;
- contain a pushed address with a numeric value smaller than `2^144`;
- point that address at a contract that already has code.

An Ethereum address is 160 bits (40 hexadecimal digits). The condition

```text
address < 2^144
```

means that the first 16 bits must be zero. In hexadecimal, the address therefore starts with four zeroes, for example:

```text
0x0000................................
```

This is called a **vanity address**. We cannot choose a normal contract address directly, so we need to search for one.

## 4. Building the forwarding contracts

There are two small contracts in the exploit:

```text
wallet -> Agent -> vanity Implementation -> BlockJail
```

The reason for using two contracts is that the validator checks the agent itself. The agent must contain exactly one `DELEGATECALL`, while the implementation can contain the ordinary `CALL` that forwards the actual function call.

### 4.1 The implementation runtime

The implementation runtime was:

```text
36 5f 5f 37 5f 5f 36 5f 5f 73 <20-byte BlockJail address> 5a f1 50 00
```

The useful opcodes are:

| Opcode | Meaning |
| --- | --- |
| `36` | Read the calldata length |
| `5f` | Push zero (`PUSH0`) |
| `37` | Copy calldata into memory |
| `73` | Push a 20-byte address (`PUSH20`) |
| `5a` | Get the remaining gas |
| `f1` | Make a normal `CALL` |
| `50` | Discard the call's success value |
| `00` | Stop |

In short, this code copies the incoming calldata and sends it to the predicted `BlockJail` address with zero ETH. It is deployed at a vanity address so the agent can push that address using `PUSH18`.

### 4.2 The final agent runtime

The agent runtime was:

```text
36 5f 5f 37 5f 5f 36 5f 71 <18-byte vanity implementation> 5a f4 00
```

This is exactly 30 bytes. The important parts are:

1. `36 5f 5f 37` copies the user's calldata into memory.
2. The next `5f 5f 36 5f` prepares zero output offset, zero output size, calldata length, and zero input offset.
3. `71` is `PUSH18`, followed by the 18-byte vanity implementation address.
4. `5a` supplies the available gas.
5. `f4` performs the one required `DELEGATECALL`.
6. `00` stops execution.

The validator sees a short contract with one delegatecall, a valid `PUSH18` address, and otherwise allowed instructions.

## 5. Finding the vanity address with `CREATE2`

### Why `CREATE2` helps

Normally, a contract address depends on the deployer's address and nonce. `CREATE2` instead lets us calculate the address before deployment from:

```text
factory address + salt + initcode
```

That allows us to try many salts locally until the resulting address starts with four zeroes. We then use the successful salt for the real deployment.

### The factory

The factory runtime used in the solve was:

```text
6020360360205f375f35602036035f5ff55f5260205ff3
```

It expects calldata in this format:

```text
32-byte salt || contract initcode
```

For a candidate salt, the predicted address is:

```text
keccak256(
    0xff || factory_address || bytes32(salt) || keccak256(implementation_initcode)
)[12:]
```

The final `[12:]` means “keep the last 20 bytes,” because Ethereum addresses are 20 bytes long.

The local search condition is:

```text
integer(predicted_address) < 2**144
```

On average, around `2^16` salts are needed. This is a small search that can be done locally; only the final deployment needs to be sent to the blockchain.

## 6. Deploying the agent and opening the path

After finding a salt and deploying the implementation at the vanity address, deploy the 30-byte agent with that implementation address embedded in its bytecode.

The calls must then be made through the agent, in this order:

```text
Agent -> enter()
Agent -> openPath()
Agent -> stealHeart()
```

### `enter()`

`enter()` checks and saves the agent address. It also saves our wallet as `beneficiary` using `tx.origin`.

### `openPath()`

This changes `BlockJail.pathOpened` to `true`, satisfying the first setup condition.

### `stealHeart()`

This sends the entire ETH balance of `BlockJail` to the saved beneficiary. After this call:

```text
BlockJail.balance == 0
```

The second setup condition is now satisfied.

## 7. Solving `PalaceVault`

The deployed palace contract's dispatcher revealed the function selector:

```text
beginInfiltration(bytes) -> 0x4b839b2c
```

The function expects a five-byte “card.” Because the source was not supplied, the card was found by making read-only probes against the deployed contract and observing which byte values and state transitions were accepted.

The successful card is:

```text
0x0001030001
```

### ABI encoding the card

A dynamic `bytes` argument is encoded as:

1. the function selector;
2. an offset to the data;
3. the length of the byte array;
4. the bytes, padded to a 32-byte boundary.

The complete calldata is:

```text
4b839b2c
0000000000000000000000000000000000000000000000000000000000000020
0000000000000000000000000000000000000000000000000000000000000005
000103000100000000000000000000000000000000000000000000000000000000
```

The last line starts with the five card bytes `00 01 03 00 01`; the remaining zeroes are padding.

Call `BlockJail.infiltrate(card)` through the agent. `BlockJail` then calls `PalaceVault.beginInfiltration(card)`. The palace sees `BlockJail` as its caller, which is the expected call path.

## 8. Complete solve sequence

```text
1. Read Setup.isSolved() and the target addresses.
2. Build a small CREATE2 factory.
3. Search locally for a salt that produces an address below 2^144.
4. Deploy the forwarding implementation at that vanity address.
5. Deploy the 30-byte agent containing the vanity address.
6. Call enter() through the agent.
7. Call openPath() through the agent.
8. Call stealHeart() through the agent.
9. Call infiltrate(0x0001030001) through the agent.
10. Check Setup.isSolved().
11. Read the flag from the challenge launcher.
```

The final checks were:

```text
BlockJail.pathOpened() == true
BlockJail.balance == 0
PalaceVault.isSolved() == true
Setup.isSolved() == true
```

## 9. Main lessons

- Contract bytecode can be inspected and reasoned about even when Solidity source is missing.
- `msg.sender` and `tx.origin` are different and can be used to satisfy different checks.
- `DELEGATECALL` preserves call context, while a nested `CALL` changes `msg.sender` to the forwarding contract.
- `CREATE2` makes it practical to search for a contract address with a desired prefix.
- Solidity's `bytes` arguments must be ABI encoded with an offset, length, and padding.
- Very small EVM programs are often enough to pass bytecode filters and create a useful call chain.

The attached Solidity files are the original challenge files. `PalaceVault.sol` was not included; its selector, accepted card, and state behavior were recovered from the deployed contract.
