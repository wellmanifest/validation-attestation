# Logic flow

1. Freeze repository, PR, head SHA and evaluated base SHA.
2. Resolve the ticket, standing grant, policy and validation profile from
   protected sources.
3. Run each digest-pinned deterministic check against the frozen candidate.
4. Record optional model analysis as advisory evidence.
5. The Validator App signs one exact-subject attestation.
6. A separate protected verifier validates signature, issuer and bindings.
7. The publisher re-resolves current state, atomically consumes the nonce and
   performs one merge only if every binding still matches.
8. Read-back confirms merge state, integrated SHA and intended effect before
   the ticket can close.

Any head update, base change, missing check, failed check, expired validity,
unknown issuer, verification failure or consumed nonce returns a stable denial.
The runtime requests a fresh validation; it does not patch the attestation.
