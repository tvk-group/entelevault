# Wallet and exchange client-integrity readiness

This gate evaluates sanitized integrity evidence for Android, iOS, browser-extension, and web clients. It never receives a device identifier, attestation token, application binary, signing credential, or key.

## Required controls

Eligibility requires all fourteen controls: official distribution, application signature, reproducible build, binary integrity, runtime attestation, hardware-backed storage, disabled debugging, root/jailbreak detection, hooking/instrumentation detection, anti-tamper, secure update, rollback protection, telemetry redaction, and independent review.

Critical/high findings, attestation failures, integrity mismatches, or unsigned builds block readiness. All 16,384 control combinations are tested; only the fully satisfied state is eligible for independent review.

The decision cannot activate or distribute a client, execute an update, access a device, store keys, deploy, sign, or move assets.
