## How to handle certificate expiry

When CI starts spuriously failing, it is usually caused by the certificates inside `src/tests/vertification_real_world` reaching their max issuance lifetime and becoming expired. While most
of our tested platforms are able to handle this better by mocking out the verification time, some can't. At the time of writing these are:
- Android ([1](https://github.com/rustls/rustls-platform-verifier/issues/59), [2](https://github.com/rustls/rustls-platform-verifier/issues/183))
- Windows ([1](https://github.com/rustls/rustls-platform-verifier/issues/117))

The other case that can cause failures (much less often) is the mock certificates expiring. Due to platform verifier security restrictions, we can't place absurdly high/unlimited expiry dates
on our mock CA and the certificates issued by it. As such, they will expire about every 2 years and need updated by hand.

Thankfully, updating these has become easy:
- If the `verification_real_world` tests are failing, do the following:
    1. Run `cargo run --example update-certs.rs`
    2. Using your tool of choice, update the hardcoded time in `verification_time` to match the current datetime.
    3. Commit your changes and push up a fix branch/PR.
- If the `verification_mock` tests are failing, do the following:
    1. Run `cd rustls-platform-verifier/src/tests/verification_mock`
    2. Run `go run ca.go`
    3. Using your tool of choice, update the hardcoded time in `verification_time` to match the current datetime.
    4. Commit your changes and push up a fix branch/PR.
