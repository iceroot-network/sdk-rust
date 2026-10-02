## Default Permission

Every command of the SDK: keys, signing, drafts, the node API client, the vote library, the
keystore and ownership proofs, except two. Connecting to a network also needs the relays it may
reach, as the `allow` scope of `allow-net-connect`: no relay is reachable by default. Reading the
recovery phrase out of a keystore, which only a backup screen needs, is `allow-keystore-decrypt`:
keys open from a keystore without it.

#### This default permission set includes the following:

- `allow-version`
- `allow-profile-capabilities`
- `allow-profile-message-network`
- `allow-profile-message-algorithm`
- `allow-phrase-generate`
- `allow-phrase-check`
- `allow-address-parse`
- `allow-address-from-public-key`
- `allow-amount-parse`
- `allow-amount-format`
- `allow-message-verify`
- `allow-signin-build`
- `allow-signin-parse`
- `allow-key-from-phrase`
- `allow-key-from-legacy-passphrase`
- `allow-key-from-keystore`
- `allow-key-sign-message`
- `allow-key-sign-sign-in`
- `allow-key-release`
- `allow-chain-load`
- `allow-chain-stage-at`
- `allow-chain-rules`
- `allow-chain-economics`
- `allow-chain-free`
- `allow-draft-build`
- `allow-draft-deserialize`
- `allow-draft-online-facts`
- `allow-draft-sign`
- `allow-signed-deserialize`
- `allow-signed-from-json`
- `allow-signed-decode`
- `allow-signed-verify-second-signature`
- `allow-net-read`
- `allow-net-node-configuration`
- `allow-net-submit`
- `allow-net-close`
- `allow-vote-call`
- `allow-vote-rules-at`
- `allow-vote-snapshot-from-validators`
- `allow-keystore-encrypt`
- `allow-keystore-inspect`
- `allow-keystore-change-password`
- `allow-keystore-reencrypt`
- `allow-keystore-armor`
- `allow-keystore-dearmor`
- `allow-keystore-check-params`
- `allow-keystore-is-weaker`
- `allow-ownership-call`
- `allow-proof-key-from-passphrase`
- `allow-proof-key-sign`
- `allow-proof-key-release`

## Permission Table

<table>
<tr>
<th>Identifier</th>
<th>Description</th>
</tr>


<tr>
<td>

`iceroot:allow-address-from-public-key`

</td>
<td>

Enables the address_from_public_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-address-from-public-key`

</td>
<td>

Denies the address_from_public_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-address-parse`

</td>
<td>

Enables the address_parse command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-address-parse`

</td>
<td>

Denies the address_parse command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-amount-format`

</td>
<td>

Enables the amount_format command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-amount-format`

</td>
<td>

Denies the amount_format command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-amount-parse`

</td>
<td>

Enables the amount_parse command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-amount-parse`

</td>
<td>

Denies the amount_parse command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-chain-economics`

</td>
<td>

Enables the chain_economics command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-chain-economics`

</td>
<td>

Denies the chain_economics command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-chain-free`

</td>
<td>

Enables the chain_free command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-chain-free`

</td>
<td>

Denies the chain_free command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-chain-load`

</td>
<td>

Enables the chain_load command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-chain-load`

</td>
<td>

Denies the chain_load command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-chain-rules`

</td>
<td>

Enables the chain_rules command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-chain-rules`

</td>
<td>

Denies the chain_rules command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-chain-stage-at`

</td>
<td>

Enables the chain_stage_at command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-chain-stage-at`

</td>
<td>

Denies the chain_stage_at command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-draft-build`

</td>
<td>

Enables the draft_build command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-draft-build`

</td>
<td>

Denies the draft_build command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-draft-deserialize`

</td>
<td>

Enables the draft_deserialize command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-draft-deserialize`

</td>
<td>

Denies the draft_deserialize command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-draft-online-facts`

</td>
<td>

Enables the draft_online_facts command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-draft-online-facts`

</td>
<td>

Denies the draft_online_facts command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-draft-sign`

</td>
<td>

Enables the draft_sign command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-draft-sign`

</td>
<td>

Denies the draft_sign command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-key-from-keystore`

</td>
<td>

Enables the key_from_keystore command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-key-from-keystore`

</td>
<td>

Denies the key_from_keystore command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-key-from-legacy-passphrase`

</td>
<td>

Enables the key_from_legacy_passphrase command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-key-from-legacy-passphrase`

</td>
<td>

Denies the key_from_legacy_passphrase command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-key-from-phrase`

</td>
<td>

Enables the key_from_phrase command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-key-from-phrase`

</td>
<td>

Denies the key_from_phrase command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-key-release`

</td>
<td>

Enables the key_release command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-key-release`

</td>
<td>

Denies the key_release command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-key-sign-message`

</td>
<td>

Enables the key_sign_message command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-key-sign-message`

</td>
<td>

Denies the key_sign_message command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-key-sign-sign-in`

</td>
<td>

Enables the key_sign_sign_in command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-key-sign-sign-in`

</td>
<td>

Denies the key_sign_sign_in command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-keystore-armor`

</td>
<td>

Enables the keystore_armor command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-keystore-armor`

</td>
<td>

Denies the keystore_armor command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-keystore-change-password`

</td>
<td>

Enables the keystore_change_password command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-keystore-change-password`

</td>
<td>

Denies the keystore_change_password command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-keystore-check-params`

</td>
<td>

Enables the keystore_check_params command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-keystore-check-params`

</td>
<td>

Denies the keystore_check_params command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-keystore-dearmor`

</td>
<td>

Enables the keystore_dearmor command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-keystore-dearmor`

</td>
<td>

Denies the keystore_dearmor command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-keystore-decrypt`

</td>
<td>

Enables the keystore_decrypt command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-keystore-decrypt`

</td>
<td>

Denies the keystore_decrypt command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-keystore-encrypt`

</td>
<td>

Enables the keystore_encrypt command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-keystore-encrypt`

</td>
<td>

Denies the keystore_encrypt command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-keystore-inspect`

</td>
<td>

Enables the keystore_inspect command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-keystore-inspect`

</td>
<td>

Denies the keystore_inspect command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-keystore-is-weaker`

</td>
<td>

Enables the keystore_is_weaker command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-keystore-is-weaker`

</td>
<td>

Denies the keystore_is_weaker command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-keystore-reencrypt`

</td>
<td>

Enables the keystore_reencrypt command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-keystore-reencrypt`

</td>
<td>

Denies the keystore_reencrypt command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-message-verify`

</td>
<td>

Enables the message_verify command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-message-verify`

</td>
<td>

Denies the message_verify command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-net-close`

</td>
<td>

Enables the net_close command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-net-close`

</td>
<td>

Denies the net_close command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-net-connect`

</td>
<td>

Enables the net_connect command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-net-connect`

</td>
<td>

Denies the net_connect command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-net-node-configuration`

</td>
<td>

Enables the net_node_configuration command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-net-node-configuration`

</td>
<td>

Denies the net_node_configuration command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-net-read`

</td>
<td>

Enables the net_read command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-net-read`

</td>
<td>

Denies the net_read command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-net-submit`

</td>
<td>

Enables the net_submit command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-net-submit`

</td>
<td>

Denies the net_submit command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-ownership-call`

</td>
<td>

Enables the ownership_call command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-ownership-call`

</td>
<td>

Denies the ownership_call command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-phrase-check`

</td>
<td>

Enables the phrase_check command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-phrase-check`

</td>
<td>

Denies the phrase_check command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-phrase-generate`

</td>
<td>

Enables the phrase_generate command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-phrase-generate`

</td>
<td>

Denies the phrase_generate command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-profile-capabilities`

</td>
<td>

Enables the profile_capabilities command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-profile-capabilities`

</td>
<td>

Denies the profile_capabilities command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-profile-message-algorithm`

</td>
<td>

Enables the profile_message_algorithm command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-profile-message-algorithm`

</td>
<td>

Denies the profile_message_algorithm command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-profile-message-network`

</td>
<td>

Enables the profile_message_network command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-profile-message-network`

</td>
<td>

Denies the profile_message_network command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-proof-key-from-passphrase`

</td>
<td>

Enables the proof_key_from_passphrase command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-proof-key-from-passphrase`

</td>
<td>

Denies the proof_key_from_passphrase command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-proof-key-release`

</td>
<td>

Enables the proof_key_release command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-proof-key-release`

</td>
<td>

Denies the proof_key_release command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-proof-key-sign`

</td>
<td>

Enables the proof_key_sign command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-proof-key-sign`

</td>
<td>

Denies the proof_key_sign command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-signed-decode`

</td>
<td>

Enables the signed_decode command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-signed-decode`

</td>
<td>

Denies the signed_decode command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-signed-deserialize`

</td>
<td>

Enables the signed_deserialize command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-signed-deserialize`

</td>
<td>

Denies the signed_deserialize command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-signed-from-json`

</td>
<td>

Enables the signed_from_json command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-signed-from-json`

</td>
<td>

Denies the signed_from_json command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-signed-verify-second-signature`

</td>
<td>

Enables the signed_verify_second_signature command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-signed-verify-second-signature`

</td>
<td>

Denies the signed_verify_second_signature command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-signin-build`

</td>
<td>

Enables the signin_build command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-signin-build`

</td>
<td>

Denies the signin_build command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-signin-parse`

</td>
<td>

Enables the signin_parse command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-signin-parse`

</td>
<td>

Denies the signin_parse command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-version`

</td>
<td>

Enables the version command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-version`

</td>
<td>

Denies the version command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-vote-call`

</td>
<td>

Enables the vote_call command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-vote-call`

</td>
<td>

Denies the vote_call command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-vote-rules-at`

</td>
<td>

Enables the vote_rules_at command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-vote-rules-at`

</td>
<td>

Denies the vote_rules_at command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:allow-vote-snapshot-from-validators`

</td>
<td>

Enables the vote_snapshot_from_validators command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:deny-vote-snapshot-from-validators`

</td>
<td>

Denies the vote_snapshot_from_validators command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`iceroot:test-seams`

</td>
<td>

The commands of the plugin's test build (the feature `test-seams`), for the SDK's own tests: signatures and ownership proofs with fixed auxiliary randomness, keystores with given salts and nonces under lowered bounds, and the constants of the vote library and the keystore. A build without the feature has none of these commands, so this permission allows nothing there. Never grant it in an application.


</td>
</tr>
</table>
