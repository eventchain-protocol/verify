// The verifier's typed results. Fault names are the specification's
// (appendix, "Refusal reasons"); `valid` is this package's name for a line
// that passed every check, which the specification leaves unnamed.

export type Fault = "chain_mismatch" | "key_off_curve" | "signature_invalid" | "attestation_fault";

export type LineOutcome = "valid" | "malformed" | Fault;

/** Flags read from a verified assertion's signed authenticator data. */
export interface AssertionFlags {
  /** UV: the authenticator performed local user verification. */
  userVerified: boolean;
  /** BE: the credential is eligible for backup. */
  backupEligible: boolean;
  /** BS: the authenticator considered the credential backed up when it signed. */
  backupState: boolean;
}

export interface MintReport {
  /** The Event ID the Mint names. */
  targetHash: string;
  /** Line of the earlier valid entry with that Event ID, or null when there is none. */
  targetLine: number | null;
  /** Present when the assertion verified. */
  flags?: AssertionFlags;
}

export interface LineReport {
  /** 1-based line number. */
  line: number;
  /** `valid`, `malformed`, or the first fault in the specification's order. */
  outcome: LineOutcome;
  /** Every fault found on a well-formed line, in the specification's order. */
  faults: Fault[];
  /** Unpadded base64url SHA-256 of the line's bytes without its terminator. Absent on a malformed line. */
  eventId?: string;
  /** Why the line is malformed or the attestation failed. */
  detail?: string;
  /** Present on a well-formed Mint entry. */
  mint?: MintReport;
}

export interface AofReport {
  /** `valid` when every line is valid. */
  outcome: "valid" | "invalid";
  /** One report per line read. Stops at the first malformed line, which rejects the file. */
  lines: LineReport[];
  /** Line number of the malformed line that rejected the file. */
  rejectedAtLine?: number;
}

export type HeartbeatOutcome = "match" | "missing" | "stale" | "conflicting" | "short" | "not_compared";

export interface HeartbeatEvidence {
  /** Index of the heartbeat among those supplied. */
  index: number;
  authenticated: boolean;
  /** Why the heartbeat does not count as authenticated. */
  reason?: string;
  position?: string;
  headHash?: string;
  issuedAt?: string;
}

export interface HeartbeatReport {
  /**
   * `match`: the copy agrees with every authenticated heartbeat it reaches, including the latest.
   * `missing`, `stale`, `conflicting`: the specification's three deficiencies.
   * `short`: the copy ends before the entry the latest heartbeat names.
   * `not_compared`: the copy is not valid through the covered entry, so there is no verified history to compare.
   */
  outcome: HeartbeatOutcome;
  detail: string;
  /** Position the latest authenticated heartbeat covers. */
  coveredPosition?: string;
  /** `not_assessed` when no freshness window was supplied. */
  freshness: "fresh" | "stale" | "not_assessed";
  heartbeats: HeartbeatEvidence[];
}
