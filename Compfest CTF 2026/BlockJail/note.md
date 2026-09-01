# BlockJail — Compfest CTF 2026

## Flag

```text
COMPFEST18{I_guess_bro_here_is_relatively_secure_mirror_flag_you_have_searched_for_0f95fd47}
```

## Challenge overview

`Setup` splits its starting ETH between a `PalaceVault` and a `BlockJail` instance. The goal is:

```solidity
TARGET.pathOpened() == true
TARGET.balance == 0
PalaceVault(PALACE).isSolved() == true
```

The supplied files do not include `PalaceVault.sol`, so its behavior has to be recovered from the deployed bytecode and by calling its public interface. `Setup` also predicts the address of `BlockJail` by assuming that its own nonce-2 contract creation is the second `CREATE` performed by the constructor.

## 1. Understanding `BlockJail`

The important functions are:

```solidity
function enter() external {
    if (agent != address(0) || msg.sender.code.length == 0) revert InvalidAgent();
    _validateAgentRuntime(msg.sender);
    agent = msg.sender;
    beneficiary = tx.origin;
}
```

An EOA cannot call `enter` directly. The caller must be a contract, and its runtime bytecode must satisfy all of these conditions:

- length is at most 36 bytes;
- exactly one `DELEGATECALL` (`0xf4`);
- every non-push opcode is in the small allowlist;
- one pushed operand is at most `2^144 - 1` and has deployed code.

The last condition is a 16-bit vanity-address requirement: a normal 160-bit address must begin with four zero hexadecimal digits. The operand can be pushed with `PUSH18`, so the agent can stay well below the 36-byte limit.

After registration, `onlyAgent` means calls must reach `BlockJail` with the agent as `msg.sender`. A delegatecall-based agent provides exactly that setup when its implementation performs an ordinary `CALL` to `BlockJail`.

## 2. The compliant agent

The agent runtime used in the solve was:

```text
36 5f 5f 37 5f 5f 36 5f 71 <18-byte vanity implementation> 5a f4 00
```

The operations are:

1. copy the caller's calldata into memory;
2. prepare a `DELEGATECALL` with the same calldata;
3. delegate once to the vanity implementation;
4. stop.

This is 30 bytes long. `0x71` is `PUSH18`, and the pushed 18-byte value is the implementation address. The implementation itself forwards calldata to the predicted `BlockJail` address:

```text
36 5f 5f 37 5f 5f 36 5f 5f 73 <20-byte TARGET> 5a f1 50 00
```

The extra `PUSH0` in this sequence is the zero `value` argument required by `CALL`.

## 3. Deploying the vanity implementation

An EOA cannot choose its contract address, so I deployed a small `CREATE2` factory first. Its runtime accepts calldata in the form:

```text
32-byte salt || initcode
```

and creates the initcode with `CREATE2`:

```text
6020360360205f375f35602036035f5ff55f5260205ff3
```

For each candidate salt, compute:

```text
address = keccak256(
    0xff || factory_address || bytes32(salt) || keccak256(implementation_initcode)
)[12:]
```

A salt is accepted when:

```text
int(address) < 2**144
```

This takes about `2^16` trials on average, but the search is entirely local and only one on-chain deployment is required. Once the code exists at the vanity address, the 30-byte agent passes `_validateAgentRuntime`.

## 4. Register and empty `BlockJail`

Call the agent with the following selectors, in order:

```text
enter()
openPath()
stealHeart()
```

`enter()` stores the agent and sets `beneficiary = tx.origin`. `openPath()` enables the remaining operations. `stealHeart()` transfers the complete `BlockJail` balance to the wallet, satisfying the `TARGET.balance == 0` part of `Setup.isSolved()`.

## 5. Recovering the palace card

The deployed `PalaceVault` dispatcher identifies `beginInfiltration(bytes)` as selector `0x4b839b2c`. The bytecode checks that the card has five bytes and performs several byte-value/state checks. Direct `eth_call` probes from the predicted target address narrow the successful card to:

```text
00 01 03 00 01
```

The call sent through `BlockJail.infiltrate(bytes)` is ABI encoded as:

```text
4b839b2c
0000000000000000000000000000000000000000000000000000000000000020
0000000000000000000000000000000000000000000000000000000000000005
000103000100000000000000000000000000000000000000000000000000000000
```

The agent forwards this calldata to `BlockJail`; `BlockJail` then calls `PalaceVault.beginInfiltration(card)`. The caller seen by `PalaceVault` is therefore the registered `BlockJail` address, while `tx.origin` remains the player's wallet.

After sending the card, both checks returned true:

```text
PalaceVault.isSolved() == true
Setup.isSolved() == true
```

The launcher then returned the flag shown above.

## Solve sequence

```text
deploy CREATE2 factory
search a salt for an address below 2^144
deploy the forwarding implementation at that address
deploy the 30-byte agent
agent -> enter()
agent -> openPath()
agent -> stealHeart()
agent -> infiltrate(0x0001030001)
query Setup.isSolved()
```

The attached Solidity files are the original challenge sources provided with the task. `PalaceVault.sol` was not included in the attachment; the card and state-machine details above were recovered from its deployed runtime bytecode.
