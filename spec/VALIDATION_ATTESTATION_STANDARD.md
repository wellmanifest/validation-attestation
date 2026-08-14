# Wellmanifest Validation Attestation Standard

Version `0.1.0-dev` defines the machine approval evidence required for a
protected autonomous publication. The key words MUST, MUST NOT, REQUIRED,
SHOULD and MAY are normative.

## 1. Purpose

A validation attestation states that an independent validator evaluated one
exact candidate under one exact policy and profile. It MAY replace repeated
human pull-request approval inside a current bounded autonomy grant. It MUST
NOT broaden that grant or authorize a different candidate.

## 2. Exact subject

An approval MUST bind all of:

- repository and pull-request number;
- candidate `headSha` and evaluated `baseSha`;
- ticket and correlation ID;
- implementer and intended publisher principals;
- grant, policy, profile and change digests.

A changed head, rebased base, changed validation profile, changed policy or
different ticket invalidates the attestation. Branch names and review prose are
not exact subject identity.

## 3. Independence

The attestation issuer MUST differ from the implementer and publisher. The
protected verifier MUST differ from the issuer and publisher. Independence is
proven through separately controlled principals and credentials, not model
diversity or role labels.

A validator MUST NOT attest changes to its own protected workflow, issuer
allowlist or verification policy unless a different validator authority is
selected by protected policy.

## 4. Checks and decision

Every required check MUST bind its command/profile digest, conclusion,
completion time and evidence digest. `approved` requires every declared check
to succeed. A skipped, missing, neutral, stale or model-only check is not a
success.

LLM findings MAY be recorded only as explicitly advisory evidence. They MUST
NOT create approval, suppress deterministic findings or satisfy a required
check.

## 5. Signature, validity and replay

An attestation MUST be signed by an allowlisted issuer and verified at a
protected boundary. Verification MUST cover signature validity, issuer trust
and resolution of the exact subject. The approval MUST have a short validity
interval, a random nonce, an exact audience and `singleUse=true`.

The publisher MUST atomically consume the nonce. A used, expired, unknown or
wrong-audience attestation MUST fail closed.

## 6. Publication and read-back

Immediately before publication, the publisher MUST resolve current repository,
PR, head, base, ticket, grant, policy and profile state and compare them with
the attestation. Publication is a separate receipt. Merge is not proof of the
intended effect; ticket closure requires subsequent read-back/EQL evidence.

## 7. Ownership

Wellmanifest owns this contract. Subactor owns Validator Apps, protected
verification, nonce storage and publication. Semcod validators MAY generate
evidence, but their model judgments remain advisory.
