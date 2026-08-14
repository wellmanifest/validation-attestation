# Architecture

```text
exact candidate + protected policy + current grant
                       |
                       v
              independent Validator App
                       |
                 signed attestation
                       |
                       v
              protected verifier + nonce store
                       |
                one-shot merge decision
                       |
                       v
               publisher -> read-back/EQL
```

The candidate checkout cannot choose trusted issuers, alter the verifier
allowlist, mark a nonce unused or create protected verification evidence. The
validator receives read access to an exact immutable candidate. The publisher
receives only a verified one-shot decision for the exact allowed effect.

An implementer, validator and publisher require different service identities.
The protected verifier is a fourth trust boundary. Running the same model under
different role names is not independence.
