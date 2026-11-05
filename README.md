# verify

An independent verifier for the [EventChain protocol](https://eventchain-protocol.github.io/),
in TypeScript. It checks an append-only file (AOF) and Hub heartbeats in Node
and in browsers, offline, and makes no network calls.

It is written from the
[specification appendix](https://eventchain-protocol.github.io/appendix-specification.html)
alone and shares no code with the
[Haskell verifier](https://github.com/eventchain-protocol/eventchain).
The two agreeing on the
[conformance vectors](https://github.com/eventchain-protocol/conformance)
is the evidence that they read the format the same way.

> [!WARNING]
> Version 0. The specification still has open points, listed under
> [Readings](#readings). Outcomes may change when they are ruled on.

## Verify a file in your browser

Open <https://eventchain-protocol.github.io/verify/#sample>. The page loads a
four-entry sample and a heartbeat and shows the report. Drop your own file on
it to check that instead. The page's Content-Security-Policy is
`default-src 'none'`, so the browser itself refuses any request the page could
make; save the page and it works from disk.

## Command line

```sh
npx @eventchain-protocol/verify aof history.jsonl
```

```text
{"line":1,"outcome":"valid","event_id":"dBnWt41McCT7DYaltzQSAi5KH4NttgOuOGKU-xuSH8k"}
{"line":2,"outcome":"valid","event_id":"SlHtaGwdfQ_0t8FVR69nzBOfBBiPko486PU_rhhfwSg"}
```

| Command | Checks | Exit 0 when |
|---|---|---|
| `aof <file>` | Every line: form, chain, producer signature, Mint assertion | every line is `valid` |
| `heartbeat <aof> <heartbeat> --hub-key K --topic T [--freshness S] [--now N]` | The copy against one heartbeat or a list | the outcome is `match` |
| `statement <file> --hub-key K` | A heartbeat, receipt or refusal under the Hub key | every statement is authentic |

Exit status is 1 when the check did not pass and 2 for a usage or IO error.
Output is minified JSON.

## Library

```ts
import { verifyAof, compareHeartbeats } from "@eventchain-protocol/verify";

const report = verifyAof(bytes); // Uint8Array: the file's exact bytes
const heartbeat = compareHeartbeats({ aof: report, heartbeats, hubKey, topicId });
```

Pass the file's bytes as read. The chain hashes exact line bytes, so a file
that was decoded, reformatted or re-terminated will not verify.

## Outcomes

Each line gets one outcome. A `malformed` line rejects the whole file and ends
the walk; any other fault is reported and the walk continues.

| Outcome | Meaning |
|---|---|
| `valid` | The line passed every check |
| `malformed` | The line is not an entry under the entry specification |
| `chain_mismatch` | `prev_hash` is not the hash of the line before it |
| `key_off_curve` | `public_key` is 33 well-formed bytes that name no point on P-256 |
| `signature_invalid` | The signature is not this key's over the line's signed message |
| `attestation_fault` | A Mint envelope failed one of the WebAuthn checks |

A Mint entry also reports the line it confirms and the `UV`, `BE` and `BS`
flags from its signed authenticator data.

A heartbeat comparison gives one of:

| Outcome | Meaning |
|---|---|
| `match` | The copy's entry at the covered position is the one the latest heartbeat names |
| `missing` | No supplied heartbeat is authenticated for this topic and Hub key |
| `stale` | The latest heartbeat is outside the freshness window |
| `conflicting` | Two heartbeats, or a heartbeat and the copy, disagree at a covered position |
| `short` | The copy ends before the entry the latest heartbeat names |
| `not_compared` | The copy is not valid through the covered entry |

This package makes no network calls, so `missing` means no authenticated
heartbeat was supplied. Retrieving one from a heartbeat host is the caller's job.

## What it does not check

Payload commitments, key registries and named attribution, OpenTimestamps
proofs, and the relying-party parts of WebAuthn (origin, RP ID, counters),
which the specification leaves to the application. A valid signature shows
that a key signed these bytes, not who holds the key or that the statement
is true.

## Readings

Where the specification names no outcome, this verifier follows the readings
recorded in the conformance repository's
[open rulings](https://github.com/eventchain-protocol/conformance#open-rulings).
Beyond those, it rejects a base64url value whose unused trailing bits are not
zero as `malformed`, treats a compressed key whose first byte is not `0x02` or
`0x03` as `malformed`, treats an empty file as valid with no entries, and
reports the first fault in the order of the table above when a line has several.

## Development

```sh
git clone --recurse-submodules https://github.com/eventchain-protocol/verify
cd verify && npm ci
npm test        # every case in conformance/manifest.jsonl
npm run site    # site/dist/index.html, one self-contained file
```

The only test is the conformance run. A case that fails is a finding about
this verifier or about the specification; it is not fixed by reading another
verifier's source.

## License

[BSD 3-Clause](LICENSE).
