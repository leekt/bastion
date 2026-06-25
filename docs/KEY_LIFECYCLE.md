# Key Lifecycle and Recovery

## Ground Rules

Bastion Secure Enclave private keys are non-exportable. A backup can preserve
configuration, policy, profile IDs, wallet-group metadata, and audit context,
but it cannot preserve signing keys.

That means key recovery is always one of these operations:

- rotate a local key while the owner still controls the Mac
- re-enroll a client onto a replacement key
- install a replacement validator on-chain
- create a replacement wallet/account when no recovery authority exists

## Private Client Key Rotation

Use this when a single private-client profile needs a fresh local signing key
and is not bound to a wallet group.

Command:

```sh
bastion rotate-client-key <profileId>
```

Flow:

1. Bastion requires owner biometric/passcode authentication.
2. Bastion creates a replacement Secure Enclave key with a fresh
   `com.bastion.signingkey.client.*` tag.
3. Bastion saves the existing `ClientProfile` with the new key tag.
4. Only after the config save succeeds, Bastion deletes the old local key.
5. Bastion records a `key_rotated` audit event and returns the old/new key tags
   plus the new derived account address when available.

This preserves the client profile, rules, bundle binding, and audit continuity.
The derived private-wallet account address changes because it is tied to the
new Secure Enclave public key.

Not supported through this command:

- wallet-group agent keys
- wallet-group owner keys
- any profile already bound to `walletGroupId`/`membershipId`

Those cases require on-chain validator state changes.

## Wallet-Group Agent Key Rotation

Use this when an agent key signs for a shared smart account through an
installed validator.

Required flow:

1. Create a replacement agent key/membership.
2. Install the replacement validator on-chain with:

```sh
bastion groups install-agent <groupId> <memberId> --chain <id> --submit
```

3. Re-pair or re-bind the client profile to the replacement installed
   membership.
4. Uninstall or revoke the old validator:

```sh
bastion groups uninstall-agent <groupId> <oldMemberId> --chain <id> --submit
```

Do not perform a local-only key swap for installed agent validators. The smart
account would still trust the old validator, while Bastion would no longer have
the matching local signing key.

## Wallet-Group Owner Key Loss

The wallet-group owner key controls sudo operations for the shared account.
If that Secure Enclave key is lost and no external on-chain recovery module or
owner authority exists, Bastion cannot locally recover or rebind the deployed
account.

Recovery options:

- use an already-installed external account recovery path, if one exists
- create a replacement wallet group
- re-enroll clients and install fresh agent validators on the replacement group
- move operational policy and audit context from the restored config backup

This is intentionally fail-closed. Bastion must not claim it can recover a
non-exportable owner key without an on-chain recovery authority.

## Replacement Mac or Lost Machine

With a config backup:

1. Install Bastion on the replacement Mac.
2. Restore the saved Bastion config for policy, profile, and wallet-group
   context.
3. Rotate or recreate private-client keys on the new machine.
4. Re-pair clients whose local key material changed.
5. Reinstall wallet-group agent validators for any deployed account that needs
   the replacement agent key.
6. Revoke old validators if the old Mac may still exist or later comes back.

Without a config backup:

1. Treat old profile IDs, policy history, and wallet-group bindings as lost.
2. Create new profiles or wallet groups.
3. Re-pair clients.
4. Reinstall validators on-chain where an owner/recovery authority exists.

## Tested Decision Contract

`KeyLifecyclePlanner` is the deterministic contract for key lifecycle decisions:

- private-client rotation is locally actionable
- wallet-group agent rotation requires on-chain validator reinstall/revoke
- wallet-group owner key loss is locally blocked
- replacement-machine recovery requires a config backup for deterministic
  profile and policy recovery

`RuleEngine.rotatePrivateClientKey` is the config mutation used by the
owner-authenticated XPC/CLI command. It refuses wallet-group profiles, saves the
new key tag before deleting the old key, and returns structured before/after
metadata.
