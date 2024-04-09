# ZK Coprocessor

## Description
ZK coprocessor offloads intensive Zero-Knowledge (ZK) computations from traditional blockchains, enabling the creation and verification of Zero-Knowledge Proofs (ZKPs) without revealing private information. Established on ICP, the ZK coprocessor is designed to be multi-chain compatible, cost-effective, and high-speed. With the ZK Coprocessor, users and developers can enjoy Web3 services with near Web2 experience, fostering a new era of privacy-first digital identity and credentials on blockchain. 
For demo application use, we built a (ZK Maze game)[https://zkmaze.zkid.app/] to show that ZK coprocessor can be seamless integrated into a project.

## Why using ICP
| Comparison (STARK proof verification) | ICP | EVM chains |
| :----- | :----- | :----- |
| Cost | as low as 2 cents | thousand of dollars |
| Efficiency | 0.2s per proof | 30s to tens of minutes |
| Interoperability | Reusable result in any **tECDSA** compatible chain | Result locked in one chain |
| UX | No gas fee, no wallet (**reverse gas**) | Install wallet and buy ETH to simply get started |

## How to Run
🫙 Canister ID (on IC main net): `7n7be-naaaa-aaaag-qc4xa-cai`.

If you want to deploy this canister locally, you can flow this flowing step:
```bash
cd icp-zk-maze/
cargo update

# if you don't have wasm32 toolchain, please install it first
rustup target add wasm32-unknown-unknown

# start ICP background locally
dfx start --clean --background

# build canister
dfx build zkmaze_backend

# deploy the zk coprocessor canister
dfx deploy zkmaze_backend
```

## How to integrate with your frontend on IC main net (e.g. TypeScript)
- Step1: get `idl_factory` and other ZK proof input data
```ts
// zk.ts
import fs from "fs";

export const programHash =
  "79414c1c82c0ef42aff896debc5b8ed351189264f32085ea5fad753b19f48d4e";

export const publicInput =
  "7,4,6,5,6,2,5,4,5,3,5,1,4,6,4,5,4,4,3,6,2,5,2,3,2,2,1,7,1,3,1,2,0,7,17,15,7,7,0,0,8,8";

export const zkp_result = fs.readFileSync("./zkpResult.json", {
  encoding: "utf-8",
});

export const canister_id = "7n7be-naaaa-aaaag-qc4xa-cai";

export const idl_factory = ({ IDL }: { IDL: any }) => {
  return IDL.Service({
    greet: IDL.Func([IDL.Text], [IDL.Text], []),
    public_key: IDL.Func(
      [],
      [
        IDL.Variant({
          Ok: IDL.Record({ public_key_hex: IDL.Text }),
          Err: IDL.Text,
        }),
      ],
      []
    ),
    zk_verify: IDL.Func(
      [IDL.Text, IDL.Text, IDL.Text],
      [IDL.Text, IDL.Text, IDL.Vec(IDL.Text)],
      []
    ),
  });
};

```

- Step2: Interact with ZK Coprocessor canister
```ts
// zkp-verify.ts
import fetch from "isomorphic-fetch";
import { Actor, HttpAgent } from "@dfinity/agent";
import {
  programHash,
  publicInput,
  zkp_result,
  canister_id,
  idl_factory,
} from "./zk";

(async () => {
  const agent = new HttpAgent({ fetch, host: "https://ic0.app" });

  const actor = Actor.createActor(idl_factory, {
    agent,
    canisterId: canister_id,
  });

  const res = await actor.zk_verify(programHash, publicInput, zkp_result);
  console.log(res);
})();

```

## ZK Coprocessor Application (ZK Maze game)
🔗 ZK Maze Github: https://github.com/zCloak-Network/ZK-Maze

🔗 ZK Maze Game: https://zkmaze.zkid.app/

🎬 Demo Video:

