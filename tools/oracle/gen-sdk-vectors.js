#!/usr/bin/env node
// gen-sdk-vectors.js: generate the SDK's own vectors (vectors/sdk/) with the reference
// implementation as the oracle.
//
//   node tools/oracle/gen-sdk-vectors.js <reference checkout> <browser wallet checkout> [out dir]
//
// <reference checkout> is a built checkout of the reference implementation (its packages/crypto
// has dist/ and node_modules/): the phrases, seeds and hardened derivations come from the
// libraries it uses itself (bip39 and @scure/bip32), and the passphrase keys, addresses and
// message signatures from its crypto package. The transactions are built and signed by its own
// transaction builders, and their fee floors come from its own transaction handlers
// (packages/transactions), under the devnet chain of Heartwood Core's vectors. <browser wallet
// checkout> holds the wallet's signing-protocol.js, whose checks give the verdicts of the sign-in
// vectors, and its legacy signer (legacy-signer/proof-protocol.js and sandbox.js), whose checks
// give the verdicts of the ownership proof vectors. The reference needs Node 18. The output is
// deterministic: running it again gives the same files.
//
// Every file is in the heartwood-vectors/1 record format: a meta record, then one record per
// case, {"op", "network", "height", "name", "input", "output"} or the same with "error" in place
// of "output".

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const [referenceDir, walletDir, outArg] = process.argv.slice(2);
if (!referenceDir || !walletDir) {
    console.error('usage: gen-sdk-vectors.js <reference checkout> <browser wallet checkout> [out dir]');
    process.exit(2);
}
const outDir = outArg || path.join(__dirname, '..', '..', 'vectors', 'sdk');
const cryptoDir = path.join(referenceDir, 'packages', 'crypto');
const load = (name) => require(require.resolve(name, { paths: [cryptoDir] }));

const bip39 = load('bip39');
const { HDKey } = load('@scure/bip32');
const reference = require(path.join(cryptoDir, 'dist', 'index.js'));
const protocolFile = path.join(walletDir, 'signing-protocol.js');
// A classic script that sets globalThis.IceRootSigning; run as it is, whatever its package's type.
new vm.Script(fs.readFileSync(protocolFile, 'utf8'), { filename: protocolFile }).runInThisContext();
const signing = globalThis.IceRootSigning;

const NETWORK_BYTE = 90;
const HARDENED = 0x80000000;
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
const packageVersion = (name) =>
    JSON.parse(fs.readFileSync(path.join(cryptoDir, 'node_modules', name, 'package.json'), 'utf8')).version;

function check(condition, message) {
    if (!condition) {
        throw new Error(`self-check failed: ${message}`);
    }
}

function meta(cls, records, extra) {
    const commit = execFileSync('git', ['-C', referenceDir, 'rev-parse', 'HEAD']).toString().trim();
    return {
        op: 'meta',
        format: 'heartwood-vectors/1',
        class: cls,
        records,
        generator: 'tools/oracle/gen-sdk-vectors.js',
        reference: {
            commit,
            bip39: packageVersion('bip39'),
            scureBip32: packageVersion('@scure/bip32'),
        },
        node: process.version,
        ...extra,
    };
}

function write(cls, records, extra = {}) {
    const lines = [meta(cls, records.length, extra), ...records].map((r) => JSON.stringify(r));
    fs.writeFileSync(path.join(outDir, `${cls}.jsonl`), lines.join('\n') + '\n');
    console.log(`${cls}: ${records.length} records`);
}

const record = (op, name, input, output) => ({ op, network: 'devnet', height: 1, name, input, output });
const refusal = (op, name, input, cls, message) => ({
    op, network: 'devnet', height: 1, name, input, error: { class: cls, message },
});

// Deterministic entropy for generated phrases.
const entropy = (label, bytes) => sha256(`iceroot-sdk vectors/${label}`).subarray(0, bytes);

function legacyKey(passphrase) {
    const keys = reference.Identities.Keys.fromPassphrase(passphrase);
    const publicKey = keys.publicKey.secp256k1;
    return { keys, publicKey, address: reference.Identities.Address.fromPublicKey(publicKey, NETWORK_BYTE) };
}

// S01: phrases. The published BIP39 vectors (English), non-ASCII passphrases, validation, and
// the genesis passphrases of Heartwood's V10 class.
function phrases() {
    const records = [];
    const published = JSON.parse(
        fs.readFileSync(path.join(__dirname, '..', '..', 'vectors', 'heartwood', 'external', 'bip39-vectors.json'), 'utf8'),
    ).english;
    published.forEach(([entropyHex, mnemonic, seedHex, xprv], index) => {
        const words = bip39.entropyToMnemonic(entropyHex);
        const seed = bip39.mnemonicToSeedSync(words, 'TREZOR');
        check(words === mnemonic, `published mnemonic ${index}`);
        check(hex(seed) === seedHex, `published seed ${index}`);
        const master = HDKey.fromMasterSeed(seed);
        check(master.privateExtendedKey === xprv, `published master key ${index}`);
        records.push(record('bip39.published', `english ${index}`, { entropy: entropyHex, passphrase: 'TREZOR' }, {
            mnemonic: words,
            seed: hex(seed),
            masterPublicKey: hex(master.publicKey),
        }));
    });

    const passphrases = [
        ['', 'no passphrase'],
        ['TREZOR', 'ascii'],
        ['Crème brûlée', 'composed accents (NFC)'],
        ['Crème brûlée', 'decomposed accents (NFD)'],
        ['㌍ガバヴァぱばぐゞちぢ十人十色', 'Japanese, NFKD changes it'],
        ['Ｔｒｅｚｏｒ', 'full-width letters'],
    ];
    for (const words of [18, 21, 24]) {
        const phrase = bip39.entropyToMnemonic(entropy(`seed ${words}`, (words / 3) * 4));
        for (const [passphrase, label] of passphrases) {
            records.push(record('bip39.mnemonicToSeed', `${words} words, ${label}`, { mnemonic: phrase, passphrase }, {
                seed: hex(bip39.mnemonicToSeedSync(phrase, passphrase)),
            }));
        }
    }

    const valid24 = bip39.entropyToMnemonic(entropy('validate', 32));
    const words24 = valid24.split(' ');
    const swapped = [words24[1], words24[0], ...words24.slice(2)].join(' ');
    const lastChanged = [...words24.slice(0, 23), words24[23] === 'zoo' ? 'zone' : 'zoo'].join(' ');
    const cases = [
        [valid24, '24 words'],
        [bip39.entropyToMnemonic(entropy('validate', 28)), '21 words'],
        [bip39.entropyToMnemonic(entropy('validate', 24)), '18 words'],
        [bip39.entropyToMnemonic(entropy('validate', 20)), '15 words'],
        [bip39.entropyToMnemonic(entropy('validate', 16)), '12 words'],
        [swapped, 'two words swapped'],
        [lastChanged, 'last word changed'],
        [[...words24.slice(0, 23), 'bitcoins'].join(' '), 'a word not in the list'],
        [words24.slice(0, 23).join(' '), '23 words'],
        [[...words24, 'abandon'].join(' '), '25 words'],
        [words24.slice(0, 11).join(' '), '11 words'],
        ['', 'empty'],
    ];
    for (const [mnemonic, name] of cases) {
        const valid = bip39.validateMnemonic(mnemonic);
        const output = { valid, words: mnemonic === '' ? 0 : mnemonic.split(' ').length };
        if (valid) {
            output.entropy = bip39.mnemonicToEntropy(mnemonic);
        }
        records.push(record('bip39.validate', name, { mnemonic }, output));
    }

    const genesis = fs
        .readFileSync(path.join(__dirname, '..', '..', 'vectors', 'heartwood', 'V10-genesis.jsonl'), 'utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line))
        .filter((r) => r.op === 'genesis.generate');
    for (const chain of genesis) {
        const out = chain.output;
        const roles = [
            ['generator', [out.generator]],
            ['genesis wallet', out.genesisWallets],
            ['donation wallet', out.donationWallets],
            ['test wallet', out.testWallets],
            ['validator', out.delegates],
        ];
        for (const [role, wallets] of roles) {
            wallets.slice(0, 3).forEach((wallet, index) => {
                const key = legacyKey(wallet.passphrase);
                check(!wallet.publicKey || wallet.publicKey === key.publicKey, `V10 ${role} public key`);
                check(!wallet.address || wallet.address === key.address, `V10 ${role} address`);
                records.push(record('genesis.passphrase', `${chain.name}, ${role} ${index}`, { passphrase: wallet.passphrase }, {
                    valid: bip39.validateMnemonic(wallet.passphrase),
                    words: wallet.passphrase.split(' ').length,
                    publicKey: key.publicKey,
                    address: key.address,
                }));
            });
        }
    }
    write('S01-phrases', records);
}

// S02: hardened derivation. The BIP32 test vectors' hardened steps, and wallet paths
// m/44'/1'/account'/0'/index' of generated phrases.
function derivation() {
    const records = [];
    const bip32 = [
        ['000102030405060708090a0b0c0d0e0f', [[], [0]], 'test vector 1'],
        ['fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542', [[]], 'test vector 2'],
        ['4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be', [[], [0]], 'test vector 3'],
        ['3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678', [[], [0], [0, 1]], 'test vector 4'],
    ];
    const published = {
        'test vector 1 m': 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
        "test vector 1 m/0'": 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
    };
    for (const [seedHex, paths, name] of bip32) {
        const master = HDKey.fromMasterSeed(Buffer.from(seedHex, 'hex'));
        for (const steps of paths) {
            const text = ['m', ...steps.map((step) => `${step}'`)].join('/');
            const node = master.derive(text);
            const label = `${name} ${text}`;
            if (published[label]) {
                check(node.privateExtendedKey === published[label], label);
            }
            records.push(record('bip32.hardened', label, { seed: seedHex, path: text, steps: steps.map((s) => s + HARDENED) }, {
                publicKey: hex(node.publicKey),
                chainCode: hex(node.chainCode),
            }));
        }
    }

    const paths = [[0, 0], [0, 1], [0, 2], [1, 0], [7, 11], [HARDENED - 1, HARDENED - 1]];
    for (const words of [18, 21, 24]) {
        const phrase = bip39.entropyToMnemonic(entropy(`wallet ${words}`, (words / 3) * 4));
        for (const passphrase of ['', 'TREZOR', 'Crème brûlée']) {
            const master = HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(phrase, passphrase));
            for (const [account, index] of paths) {
                const text = `m/44'/1'/${account}'/0'/${index}'`;
                const node = master.derive(text);
                const publicKey = hex(node.publicKey);
                const keys = reference.Identities.Keys.fromPrivateKey(hex(node.privateKey));
                check(keys.publicKey.secp256k1 === publicKey, `the reference's key of ${text}`);
                records.push(record('wallet.derive', `${words} words, passphrase ${JSON.stringify(passphrase)}, ${text}`, {
                    mnemonic: phrase, passphrase, coinType: 1, account, index,
                }, {
                    path: text,
                    publicKey,
                    address: reference.Identities.Address.fromPublicKey(publicKey, NETWORK_BYTE),
                }));
            }
        }
    }
    const twelve = bip39.entropyToMnemonic(entropy('wallet 12', 16));
    records.push(refusal('wallet.derive', '12 words', { mnemonic: twelve, passphrase: '', coinType: 1, account: 0, index: 0 },
        'PhraseTooShort', 'phrases under 18 words are refused'));
    const valid = bip39.entropyToMnemonic(entropy('wallet 24', 32));
    records.push(refusal('wallet.derive', 'index 2^31', { mnemonic: valid, passphrase: '', coinType: 1, account: 0, index: HARDENED },
        'InvalidPath', 'only hardened steps below 2^31 exist'));
    records.push(refusal('wallet.derive', 'account 2^31', { mnemonic: valid, passphrase: '', coinType: 1, account: HARDENED, index: 0 },
        'InvalidPath', 'only hardened steps below 2^31 exist'));
    write('S02-derivation', records);
}

// S03: message signatures, the reference's Message.sign with a fixed aux, and its Message.verify.
function messages() {
    const records = [];
    const aux = Buffer.alloc(32, 0x42);
    const signers = ['this is a top secret passphrase', 'heartwood message domain'];
    const texts = [
        ['IceRoot sign-in test', 'short'],
        ['', 'empty'],
        ['0123456789abcdef0123456789abcdef', 'exactly 32 bytes'],
        ['ünïcödé ✓', 'unicode'],
        ['line one\nline two\n', 'newlines'],
        ['x'.repeat(1000), '1000 bytes'],
    ];
    for (const passphrase of signers) {
        const key = legacyKey(passphrase);
        for (const [message, label] of texts) {
            const hash = reference.Crypto.HashAlgorithms.sha256(message);
            const signature = reference.Crypto.Hash.signSchnorr(hash, key.keys, true, aux);
            const verified = reference.Crypto.Message.verify({ message, publicKey: key.publicKey, signature });
            check(verified, `own signature verifies: ${label}`);
            records.push(record('message.sign', `${label}, ${passphrase}`, { passphrase, message, aux: hex(aux) }, {
                publicKey: key.publicKey, address: key.address, signature,
            }));
            // A second signature with another aux, as Message.sign makes with a random one.
            const otherAux = sha256(`aux/${label}/${passphrase}`);
            const second = {
                message, publicKey: key.publicKey, signature: reference.Crypto.Hash.signSchnorr(hash, key.keys, true, otherAux),
            };
            records.push(record('message.verify', `${label}, ${passphrase}, another aux`, second, {
                valid: reference.Crypto.Message.verify(second),
            }));
            const tampered = { message: `${message}.`, publicKey: second.publicKey, signature: second.signature };
            records.push(record('message.verify', `${label}, ${passphrase}, message changed`, tampered, {
                valid: reference.Crypto.Message.verify(tampered),
            }));
        }
    }
    const key = legacyKey(signers[0]);
    const other = legacyKey(signers[1]);
    const signature = reference.Crypto.Hash.signSchnorr(reference.Crypto.HashAlgorithms.sha256('x'), key.keys, true, aux);
    const flipped = signature.slice(0, 127) + (signature[127] === '0' ? '1' : '0');
    for (const [input, name] of [
        [{ message: 'x', publicKey: other.publicKey, signature }, 'another key'],
        [{ message: 'x', publicKey: key.publicKey, signature: flipped }, 'signature changed'],
        [{ message: 'x', publicKey: key.publicKey.slice(2), signature }, 'x-only key'],
        [{ message: 'x', publicKey: `02${key.publicKey.slice(2)}`, signature }, 'prefix changed'],
    ]) {
        records.push(record('message.verify', name, input, { valid: reference.Crypto.Message.verify(input) }));
    }
    write('S03-messages', records, { aux: hex(aux) });
}

// S04: sign-in messages, with the verdicts of the wallet's signing-protocol.js.
function signIn() {
    const records = [];
    const key = legacyKey('this is a top secret passphrase');
    const other = legacyKey('heartwood message domain');
    const nonce = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
    const issued = Date.parse('2026-09-26T12:34:56Z');
    const iso = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
    const build = (fields = {}) => {
        const f = {
            origin: 'https://validators.example', network: 'heartwood-devnet-v90', publicKey: key.publicKey,
            address: key.address, nonce, issued: iso(issued), expires: iso(issued + 300000), ...fields,
        };
        return [
            'IceRoot Validator Portal sign-in', 'Version: 1', `Origin: ${f.origin}`, `URI: ${f.uri || `${f.origin}/login`}`,
            `Network: ${f.network}`, `Public key: ${f.publicKey}`, `Address: ${f.address}`, `Nonce: ${f.nonce}`,
            `Issued at: ${f.issued}`, `Expires at: ${f.expires}`,
            'Intent: Sign in to manage your validator proposal and contributions.', 'No transaction or transfer is authorized.',
        ].join('\n');
    };
    const now = issued + 1000;
    const all = { origin: 'https://validators.example', publicKey: key.publicKey, address: key.address };
    const cases = [
        [build(), {}, now, 'valid'],
        [build(), all, now, 'valid, identity expected'],
        [build({ origin: 'http://localhost:3000' }), {}, now, 'http on localhost'],
        [build({ origin: 'http://127.0.0.1:8080' }), {}, now, 'http on 127.0.0.1'],
        [build({ origin: 'https://a.b.example:8443' }), {}, now, 'https with a port'],
        [build(), { origin: 'https://evil.example' }, now, 'another origin expected'],
        [build(), { address: other.address }, now, 'another address expected'],
        [build(), { publicKey: other.publicKey }, now, 'another key expected'],
        [`${build()}\n`, {}, now, 'trailing newline'],
        [build().replace(/\n/g, '\r\n'), {}, now, 'CRLF'],
        [build().replace('Version: 1', 'Version: 2'), {}, now, 'version 2'],
        [build().replace('Nonce: ', 'Nonce:'), {}, now, 'field without its space'],
        [build({ origin: 'http://validators.example' }), {}, now, 'http elsewhere'],
        [build({ origin: 'https://validators.example/' }), {}, now, 'origin with a slash'],
        [build({ origin: 'https://validators.example:443' }), {}, now, 'default port'],
        [build({ origin: 'https://Validators.example' }), {}, now, 'upper-case host'],
        [build({ uri: 'https://validators.example/logout' }), {}, now, 'another URI'],
        [build({ network: 'heartwood-devnet-v63' }), {}, now, 'another network'],
        [build({ publicKey: key.publicKey.toUpperCase() }), {}, now, 'upper-case key'],
        [build({ publicKey: `04${key.publicKey.slice(2)}` }), {}, now, 'key prefix 04'],
        [build({ nonce: nonce.slice(1) }), {}, now, 'short nonce'],
        [build({ nonce: nonce.toUpperCase() }), {}, now, 'upper-case nonce'],
        [build({ address: 'not-base58!' }), {}, now, 'malformed address'],
        [build(), {}, issued + 300000, 'expired'],
        [build(), {}, issued + 299999, 'last millisecond'],
        [build(), {}, issued - 30001, 'issued too far ahead'],
        [build(), {}, issued - 30000, 'issued 30 seconds ahead'],
        [build({ expires: iso(issued + 306000) }), {}, now, 'valid for 306 seconds'],
        [build({ expires: iso(issued + 305000) }), {}, now, 'valid for 305 seconds'],
        [build({ expires: iso(issued) }), {}, now, 'expires when issued'],
        [build({ issued: iso(issued - 306000), expires: iso(issued + 100) }), {}, issued, 'issued 306 seconds ago'],
        [build({ issued: '2026-09-26T14:34:56+02:00' }), {}, now, 'issued with an offset'],
        [build({ issued: 'yesterday' }), {}, now, 'not a time'],
        [build() + ' '.repeat(4096), {}, now, 'over 4096 characters'],
        [build({ address: other.address }), {}, now, "another key's address"],
    ];
    for (const [message, expected, at, name] of cases) {
        const input = { message, expected, now: at };
        try {
            const fields = signing.challenge(message, expected, at);
            records.push(record('signin.parse', name, input, {
                ...fields, issuedAtMs: Date.parse(fields.issuedAt), expiresAtMs: Date.parse(fields.expiresAt),
            }));
        } catch (error) {
            records.push(refusal('signin.parse', name, input, 'refused', error.message));
        }
    }
    write('S04-signin', records, { signingProtocolSha256: hex(sha256(fs.readFileSync(protocolFile))) });
}

// ---- transactions -------------------------------------------------------------------------------
//
// The classes below run the reference's transaction builders and handlers under the devnet chain
// that Heartwood Core's vectors use: the network description and milestones of the first chain of
// its V10 class, whose milestones hash the meta record names. Signatures take the fixed aux 0x42 x
// 32, as Heartwood Core's oracle signs; the SDK signs its drafts with the same aux to compare.

const TX_HEIGHT = 2;
const FIXED_AUX = Buffer.alloc(32, 0x42);
const RESIGNATION_TYPES = { temporary: 0, permanent: 1, revoke: 2 };

let devnetChain;
function devnet() {
    if (!devnetChain) {
        const genesis = fs
            .readFileSync(path.join(__dirname, '..', '..', 'vectors', 'heartwood', 'V10-genesis.jsonl'), 'utf8')
            .trim()
            .split('\n')
            .map((line) => JSON.parse(line))
            .find((r) => r.op === 'genesis.generate');
        const files = genesis.output.files;
        const config = {
            network: JSON.parse(files['crypto/network.json']),
            milestones: JSON.parse(files['crypto/milestones.json']),
            genesisBlock: JSON.parse(files['crypto/genesisBlock.json']),
            exceptions: JSON.parse(files['crypto/exceptions.json']),
        };
        reference.Managers.configManager.setConfig(config);
        reference.Managers.configManager.setHeight(TX_HEIGHT);
        check(config.network.pubKeyHash === NETWORK_BYTE, 'the devnet network byte');
        // Signatures of the transaction builders, which pass no aux, take the fixed aux. Only in
        // this process; the other classes pass their aux explicitly.
        const Hash = reference.Crypto.Hash;
        const original = Hash.signSchnorrBip340;
        Hash.signSchnorrBip340 = (hash, keys, aux) => original.call(Hash, hash, keys, aux ?? FIXED_AUX);
        devnetChain = {
            milestonesSha256: hex(sha256(files['crypto/milestones.json'])),
            wif: config.network.wif,
        };
    }
    return devnetChain;
}

let registry;
// The reference's transaction handlers, without the node's container: each handler's
// getMinimumFee is the pool's fee floor, and it reads nothing but the transaction and the table.
function handlerRegistry() {
    if (!registry) {
        const transactionsDir = path.join(referenceDir, 'packages', 'transactions');
        const { Handlers } = require(path.join(transactionsDir, 'dist', 'index.js'));
        const shared = require(require.resolve('@solar-network/crypto', { paths: [transactionsDir] }));
        check(shared === reference, 'the transaction handlers load the same crypto package');
        registry = Object.create(Handlers.Registry.prototype);
        registry.provider = { isRegistrationRequired: () => false, registerHandlers: () => {} };
        registry.handlers = [...Object.values(Handlers.Core), ...Object.values(Handlers.Solar)].map((H) =>
            Object.create(H.prototype),
        );
    }
    return registry;
}

/** The reference's fee floor of a built transaction at the vectors' height. */
function minimumFee(tx) {
    const type = reference.Transactions.InternalTransactionType.from(tx.data.type, tx.data.typeGroup);
    const handler = handlerRegistry().getRegisteredHandlerByType(type);
    const table = reference.Managers.configManager.getMilestone(TX_HEIGHT).dynamicFees;
    return handler.getMinimumFee(tx, table).toString();
}

// Signers: legacy passphrase keys (the devnet tooling's genesis wallets are such keys) and new
// accounts, derived with hardened steps from a recovery phrase.
const PASSPHRASE = 'this is a top secret passphrase';
const SECOND_PASSPHRASE = 'heartwood message domain';
const WALLET_PHRASE = bip39.entropyToMnemonic(entropy('transactions 24', 32));
const WALLET_PHRASE_18 = bip39.entropyToMnemonic(entropy('transactions 18', 24));

function signer(spec) {
    if (spec.passphrase !== undefined && spec.mnemonic === undefined) {
        const key = legacyKey(spec.passphrase);
        return { spec, keys: key.keys, publicKey: key.publicKey, address: key.address };
    }
    const seed = bip39.mnemonicToSeedSync(spec.mnemonic, spec.passphrase);
    const node = HDKey.fromMasterSeed(seed).derive(`m/44'/1'/${spec.account}'/0'/${spec.index}'`);
    const keys = reference.Identities.Keys.fromPrivateKey(hex(node.privateKey));
    const publicKey = keys.publicKey.secp256k1;
    return { spec, keys, publicKey, address: reference.Identities.Address.fromPublicKey(publicKey, NETWORK_BYTE) };
}

const legacySigner = (passphrase) => signer({ passphrase });
const walletSigner = (account, index, mnemonic = WALLET_PHRASE, passphrase = '') =>
    signer({ mnemonic, passphrase, account, index });

// Recipients: addresses of legacy keys, so that anyone can check them.
const recipient = (n) => legacyKey(`iceroot-sdk vectors/recipient ${n}`).address;
const validator = (n) => `genesis_${n}`;

/**
 * The reference's transaction for an SDK request, or the error it throws. `second` signs as the
 * sender's second key. The fee is `fee` when given, else the reference's own floor of the
 * transaction (built once to learn its size; the fee field has a fixed width).
 */
function referenceTransaction({ operation, memo, nonce, fee }, sender, second) {
    const B = reference.Transactions.BuilderFactory;
    const build = (feeText) => {
        let b;
        switch (operation.kind) {
            case 'transfer':
                b = B.transfer();
                for (const { address, amount } of operation.to) {
                    b = b.addTransfer(address, amount);
                }
                break;
            case 'vote':
                b = B.vote().votesAsset(
                    Object.fromEntries(operation.entries.map(({ validator: name, basisPoints }) => [name, basisPoints / 100])),
                );
                break;
            case 'burn':
                b = B.burn().amount(operation.amount);
                break;
            case 'register-second-key':
                b = B.secondSignature();
                b.data.asset.signature.publicKey = operation.publicKey;
                break;
            case 'register-validator':
                b = B.delegateRegistration().usernameAsset(operation.name);
                break;
            case 'resign-validator':
                b = B.delegateResignation().resignationTypeAsset(RESIGNATION_TYPES[operation.resignation]);
                break;
            default:
                throw new Error(`no builder for ${operation.kind}`);
        }
        b = b.nonce(nonce).fee(feeText);
        if (memo !== null) {
            b = b.memo(memo);
        }
        b = sender.spec.mnemonic === undefined
            ? b.sign(sender.spec.passphrase)
            : b.signWithWif(reference.Identities.WIF.fromKeys(sender.keys, { wif: devnet().wif }));
        if (second !== undefined) {
            b = b.secondSign(second.spec.passphrase);
        }
        return b.build();
    };
    const floor = minimumFee(build('1'));
    const tx = build(fee ?? floor);
    check(tx.isVerified, `the reference verifies its own ${operation.kind}`);
    const unsigned = reference.Transactions.Serialiser.getBytes(tx.data, { excludeSignature: true, excludeSecondSignature: true });
    return { tx, floor, unsigned: hex(unsigned) };
}

/** A case of S05 or S06: the SDK's request and facts, and the reference's outcome. */
function transactionCase(op, name, { operation, memo = null, sender, second, nonce = '1', fee }, output) {
    const request = { operation, memo, nonce, fee };
    const input = {
        signer: sender.spec,
        ...(second === undefined ? {} : { secondSigner: second.spec }),
        request: { operation, memo },
        facts: { nonce, height: TX_HEIGHT, ...(second === undefined ? {} : { secondKey: second.publicKey }) },
        aux: hex(FIXED_AUX),
    };
    let built;
    try {
        built = referenceTransaction(request, sender, second);
    } catch (error) {
        return {
            op, network: 'devnet', height: TX_HEIGHT, name, input,
            error: { class: error.constructor.name, message: String(error.message) },
        };
    }
    input.request.fee = { kind: 'exact', amount: built.tx.data.fee.toString() };
    return { op, network: 'devnet', height: TX_HEIGHT, name, input, output: output(built) };
}

// S05: transactions of the six operations, signed by legacy and derived keys, with and without a
// second signature, at the edges the rules draw: recipients, memo bytes and vote entries. Each pays
// exactly the reference's fee floor. Requests the reference refuses are recorded with its error.
function transactions() {
    const chain = devnet();
    const legacy = legacySigner(PASSPHRASE);
    const secondKey = legacySigner(SECOND_PASSPHRASE);
    const wallet = walletSigner(0, 0);
    const walletPassphrase = walletSigner(3, 7, WALLET_PHRASE_18, 'TREZOR');
    const transfer = (count, amount = (i) => String(100000000 + i)) => ({
        kind: 'transfer',
        to: Array.from({ length: count }, (_, i) => ({ address: recipient(i), amount: amount(i) })),
    });
    const vote = (count, basisPoints) => ({
        kind: 'vote',
        // Given in reverse order: the SDK and the reference both sort the entries.
        entries: Array.from({ length: count }, (_, i) => ({ validator: validator(count - i), basisPoints: basisPoints(count - 1 - i) })),
    });
    const even = (count) => (i) => Math.trunc(10000 / count) + (i < 10000 % count ? 1 : 0);
    const cases = [
        ['transfer to one recipient', { operation: transfer(1), sender: legacy }],
        ['transfer to one recipient, empty memo', { operation: transfer(1), memo: '', sender: legacy }],
        ['transfer to one recipient, one-byte memo', { operation: transfer(1), memo: 'x', sender: legacy }],
        ['transfer to two recipients, 255-byte memo', { operation: transfer(2), memo: 'm'.repeat(255), sender: wallet }],
        ['transfer, 255-byte memo of 3-byte characters', { operation: transfer(1), memo: '✓'.repeat(85), sender: wallet }],
        ['transfer, 256-byte memo', { operation: transfer(1), memo: 'm'.repeat(256), sender: wallet }],
        ['transfer, 256-byte memo of 4-byte characters', { operation: transfer(1), memo: '\u{1F332}'.repeat(64), sender: wallet }],
        ['transfer to 256 recipients', { operation: transfer(256, (i) => String(i + 1)), sender: wallet, nonce: '42' }],
        ['transfer to 257 recipients', { operation: transfer(257, (i) => String(i + 1)), sender: wallet }],
        ['transfer from a derived account with a BIP39 passphrase', { operation: transfer(3), memo: 'derived', sender: walletPassphrase }],
        ['transfer signed with a second key', { operation: transfer(1), memo: 'second', sender: legacy, second: secondKey }],
        ['transfer to two recipients from a derived account, second-signed', { operation: transfer(2), sender: wallet, second: secondKey, nonce: '9' }],
        ['vote for one validator', { operation: vote(1, () => 10000), sender: legacy }],
        ['vote for 20 validators at 500 basis points', { operation: vote(20, () => 500), sender: wallet }],
        ['vote for 53 validators', { operation: vote(53, even(53)), sender: wallet }],
        ['vote for 54 validators', { operation: vote(54, even(54)), sender: wallet }],
        ['vote withdrawal', { operation: { kind: 'vote', entries: [] }, sender: wallet }],
        ['vote, second-signed', { operation: vote(3, (i) => [5000, 2500, 2500][i]), sender: legacy, second: secondKey }],
        ['burn of the smallest amount', { operation: { kind: 'burn', amount: '2000000' }, sender: legacy }],
        ['burn with a memo, second-signed', { operation: { kind: 'burn', amount: '123456789' }, memo: 'burn', sender: wallet, second: secondKey }],
        ['second key registration', { operation: { kind: 'register-second-key', publicKey: secondKey.publicKey }, sender: wallet }],
        ['validator registration', { operation: { kind: 'register-validator', name: 'sdk_validator' }, sender: wallet }],
        ['validator registration, second-signed', { operation: { kind: 'register-validator', name: 'a.b!c@d$e&f_1' }, sender: legacy, second: secondKey }],
        ['temporary resignation', { operation: { kind: 'resign-validator', resignation: 'temporary' }, sender: wallet }],
        ['permanent resignation', { operation: { kind: 'resign-validator', resignation: 'permanent' }, sender: legacy }],
        ['revoke of a resignation, second-signed', { operation: { kind: 'resign-validator', resignation: 'revoke' }, sender: wallet, second: secondKey }],
    ];
    const records = cases.map(([name, spec]) =>
        transactionCase('sdk.transaction', name, spec, ({ tx, unsigned }) => ({
            unsigned,
            size: tx.serialised.length,
            id: tx.id,
            hex: tx.serialised.toString('hex'),
            json: JSON.parse(JSON.stringify(tx.toJson())),
        })),
    );
    write('S05-transactions', records, { network: { name: 'devnet', pubKeyHash: NETWORK_BYTE, milestonesSha256: chain.milestonesSha256 }, aux: hex(FIXED_AUX) });
}

// S06: the fee floor of every operation at sizes around the rounding of half the size: memos of
// 0 to 3 bytes and of 254 and 255 bytes, with and without a second signature, plus transfers and
// votes of a few more entries. The transaction pays its floor.
function feeFloors() {
    const chain = devnet();
    const legacy = legacySigner(PASSPHRASE);
    const secondKey = legacySigner(SECOND_PASSPHRASE);
    const wallet = walletSigner(0, 0);
    const operations = [
        ['transfer', { kind: 'transfer', to: [{ address: recipient(0), amount: '100000000' }] }],
        ['transfer to three recipients', { kind: 'transfer', to: [0, 1, 2].map((i) => ({ address: recipient(i), amount: '1' })) }],
        ['vote', { kind: 'vote', entries: [{ validator: validator(7), basisPoints: 10000 }] }],
        ['vote for two', { kind: 'vote', entries: [{ validator: validator(12), basisPoints: 4000 }, { validator: validator(3), basisPoints: 6000 }] }],
        ['vote withdrawal', { kind: 'vote', entries: [] }],
        ['burn', { kind: 'burn', amount: '2000000' }],
        ['second key registration', { kind: 'register-second-key', publicKey: secondKey.publicKey }],
        ['validator registration', { kind: 'register-validator', name: 'floor_validator' }],
        ['temporary resignation', { kind: 'resign-validator', resignation: 'temporary' }],
        ['revoke', { kind: 'resign-validator', resignation: 'revoke' }],
    ];
    const records = [];
    for (const [label, operation] of operations) {
        for (const memoBytes of [0, 1, 2, 3, 254, 255]) {
            for (const [sender, second, how] of [
                [wallet, undefined, 'single'],
                [legacy, secondKey, 'second-signed'],
            ]) {
                // Registering a second key is refused by the rules when the sender already has one.
                if (operation.kind === 'register-second-key' && second !== undefined) {
                    continue;
                }
                const memo = memoBytes === 0 ? null : 'f'.repeat(memoBytes);
                records.push(
                    transactionCase('fee.floor', `${label}, memo of ${memoBytes} bytes, ${how}`, { operation, memo, sender, second }, ({ tx, floor, unsigned }) => ({
                        unsigned,
                        size: tx.serialised.length,
                        floor,
                    })),
                );
            }
        }
    }
    for (const record of records) {
        check(record.output !== undefined, `the reference builds ${record.name}`);
    }
    // Both parities of the size occur for every operation.
    const parities = new Map();
    for (const record of records) {
        const kind = record.input.request.operation.kind;
        parities.set(kind, new Set([...(parities.get(kind) ?? []), record.output.size % 2]));
    }
    for (const [kind, seen] of parities) {
        check(seen.size === 2, `odd and even sizes of ${kind}`);
    }
    write('S06-fee-floor', records, { network: { name: 'devnet', pubKeyHash: NETWORK_BYTE, milestonesSha256: chain.milestonesSha256 }, aux: hex(FIXED_AUX) });
}

// ---- ownership proofs ------------------------------------------------------------------------
//
// S08: ownership proofs of Solar addresses, version 1: the migration ownership proofs of the
// browser wallet's legacy signer. The verdicts on messages and signed proofs come from the legacy
// signer's own scripts: proof-protocol.js (the format) and sandbox.js (signing, and checking a
// signature made elsewhere), run in a context of their own with the reference's crypto package in
// place of the Solar bundle the signer loads, and a clock set to each record's time. Keys, Solar
// mainnet addresses (network byte 63) and signatures come from the reference; signatures take the
// fixed aux 0x42 x 32. IceRoot accounts are encoded with the bech32m of @scure/base, the library
// under the reference's own @scure/bip32. Runs last: the sandbox sets the reference's network to
// mainnet.

const SOLAR_MAINNET = 63;

function legacySignerScripts() {
    const dir = path.join(walletDir, 'legacy-signer');
    const files = ['proof-protocol.js', 'sandbox.js'].map((name) => path.join(dir, name));
    let handler;
    const context = { SolarCrypto: reference, __now: 0 };
    context.window = context;
    context.parent = { postMessage: (reply) => { context.reply = reply; } };
    context.addEventListener = (type, listener) => {
        if (type === 'message') {
            handler = listener;
        }
    };
    vm.createContext(context);
    new vm.Script('Date.now = () => globalThis.__now;').runInContext(context);
    for (const file of files) {
        new vm.Script(fs.readFileSync(file, 'utf8'), { filename: file }).runInContext(context);
    }
    check(typeof handler === 'function', 'the sandbox listens for requests');
    // One request to the sandbox, as the signer page makes it, at the time `now`.
    const call = (op, args, now) => {
        context.__now = now;
        context.reply = undefined;
        handler({ source: context.parent, data: { __legacySigner: 1, id: 1, op, args } });
        const reply = context.reply;
        if (!reply.ok) {
            throw new Error(reply.error);
        }
        return reply.result;
    };
    check(call('ping', {}, 0).ready === true, 'the sandbox loads the reference');
    const hashes = Object.fromEntries(files.map((file) => [path.basename(file), hex(sha256(fs.readFileSync(file)))]));
    return { Proof: context.IceRootLegacyProof, call, hashes };
}

function ownershipProofs() {
    const { Proof, call, hashes } = legacySignerScripts();
    const bip32Dir = path.dirname(require.resolve('@scure/bip32', { paths: [cryptoDir] }));
    const baseEntry = require.resolve('@scure/base', { paths: [bip32Dir] });
    const { bech32, bech32m } = require(baseEntry);
    const basePackage = JSON.parse(fs.readFileSync(path.join(path.dirname(baseEntry), '..', 'package.json'), 'utf8'));
    check(basePackage.name === '@scure/base', 'the package of @scure/base');

    const records = [];
    const aux = FIXED_AUX;
    const refused = (op, name, input, error) => records.push(refusal(op, name, input, 'refused', error.message));
    const solarKey = (passphrase) => {
        const keys = reference.Identities.Keys.fromPassphrase(passphrase);
        const publicKey = keys.publicKey.secp256k1;
        const key = { passphrase, keys, publicKey, address: reference.Identities.Address.fromPublicKey(publicKey, SOLAR_MAINNET) };
        const fromSandbox = call('phraseAccount', { phrase: passphrase }, 0);
        check(fromSandbox.address === key.address && fromSandbox.publicKey === publicKey, `the sandbox's address of ${passphrase}`);
        check(key.address.startsWith('S'), 'a Solar mainnet address');
        return key;
    };
    const hashOf = (label) => sha256(`iceroot-sdk vectors/${label}`);
    const accountOf = (prefix, label) => bech32m.encode(prefix, bech32m.toWords(hashOf(`account ${label}`)));
    const nonceOf = (label) => hex(hashOf(`nonce ${label}`));
    const iso = (ms) => new Date(ms).toISOString();

    // The legacy signer's own test key and account, and its fixed proof.
    const wallet = solarKey('this is a top secret passphrase');
    check(wallet.address === 'SNAgA2XCRZDKfm5Vu9h4KR1bZw5xn9EiC3', "the legacy signer's test address");
    const walletAccount = 'ice1q8y55x5z8dr5uepshat727uvt328lfkklzwvvmt4p42qlcrggxtsk8zw2r';
    const keys = [
        wallet,
        solarKey(bip39.entropyToMnemonic(entropy('solar 12', 16))),
        solarKey('Crème brûlée ✓'),
    ];
    const other = solarKey('another passphrase');
    const mainnet = [accountOf('ice', 0), accountOf('ice', 1)];
    const testnet = [accountOf('tice', 0), accountOf('tice', 1)];
    const issued = Date.parse('2026-09-01T12:00:00Z');
    const compose = (fields) => Proof.compose({
        address: wallet.address, account: mainnet[0], nonce: nonceOf(0), issuedAt: iso(issued), ...fields,
    });

    // proof.account: the IceRoot account as a person types it.
    let kelvin = 0;
    while (!accountOf('ice', `kelvin ${kelvin}`).slice(4).includes('k')) {
        kelvin += 1;
    }
    const withK = accountOf('ice', `kelvin ${kelvin}`);
    const mixed = mainnet[0].slice(0, 5) + mainnet[0].slice(5).replace(/[a-z]/, (c) => c.toUpperCase());
    check(mixed !== mainnet[0], 'a mixed-case account');
    const typo = (() => {
        const data = [...mainnet[0]];
        data[10] = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'[('qpzry9x8gf2tvdw0s3jn54khce6mua7l'.indexOf(data[10]) + 1) % 32];
        return data.join('');
    })();
    const spareWords = bech32m.toWords(hashOf('account spare'));
    spareWords[51] |= 1;
    const accountCases = [
        [mainnet[0], 'mainnet'],
        [mainnet[1], 'mainnet, another'],
        [testnet[0], 'testnet'],
        [testnet[1], 'testnet, another'],
        [walletAccount, "the legacy signer's test account"],
        [mainnet[0].toUpperCase(), 'in capitals'],
        [testnet[0].toUpperCase(), 'testnet in capitals'],
        [` \t${mainnet[0]}\n`, 'surrounded by white space'],
        [`﻿${mainnet[0]}　`, 'a byte order mark and an ideographic space around it'],
        [`\u0085${mainnet[0]}`, 'a next-line character before it'],
        [withK.toUpperCase().replace('K', 'K'), 'in capitals with a Kelvin sign for K'],
        [mixed, 'mixed case'],
        [`ICE1${mainnet[0].slice(4)}`, 'prefix in capitals only'],
        [typo, 'one character changed'],
        [bech32.encode('ice', bech32m.toWords(hashOf('account 0'))), 'a Bech32 checksum, not Bech32m'],
        [bech32m.encode('ice', spareWords), 'spare bits set'],
        [bech32m.encode('ice', bech32m.toWords(hashOf('account 20').subarray(0, 20))), 'a 20-byte hash'],
        [bech32m.encode('ice', bech32m.toWords(Buffer.concat([hashOf('account 33'), Buffer.from([0])]))), 'a 33-byte hash'],
        [`t${mainnet[0]}`, 'a mainnet account under the testnet prefix'],
        [bech32m.encode('bc', bech32m.toWords(hashOf('account 0'))), 'another prefix'],
        [mainnet[0].replace('1', ''), 'no separator'],
        ['', 'empty'],
    ];
    for (const [text, name] of accountCases) {
        try {
            const account = Proof.account(text);
            records.push(record('proof.account', name, { text }, { account: account.account, network: account.network }));
        } catch (error) {
            refused('proof.account', name, { text }, error);
        }
    }

    // A Solar-looking address of another network byte, which the format's pattern accepts.
    let probe = 0;
    let otherByte;
    while (!otherByte) {
        const publicKey = reference.Identities.Keys.fromPassphrase(`network byte probe ${probe}`).publicKey.secp256k1;
        const address = reference.Identities.Address.fromPublicKey(publicKey, 62);
        if (address.startsWith('S')) {
            otherByte = address;
        }
        probe += 1;
    }
    const badChecksum = wallet.address.slice(0, 33) + (wallet.address[33] === 'z' ? 'y' : 'z');

    // proof.build: the legacy signer's compose, refused when its parse refuses the result.
    const builds = [
        [{ address: wallet.address, account: walletAccount, nonce: '7e'.repeat(32), issuedAtMs: issued }, "the legacy signer's fixed proof"],
        [{ address: keys[1].address, account: mainnet[0], nonce: nonceOf(1), issuedAtMs: Date.parse('2026-09-27T08:15:30.123Z') }, 'mainnet account'],
        [{ address: keys[2].address, account: testnet[0], nonce: nonceOf(2), issuedAtMs: 0 }, 'testnet account, 1970'],
        [{ address: wallet.address, account: mainnet[1], nonce: nonceOf(3), issuedAtMs: Date.parse('9999-12-31T23:59:59.999Z') }, 'the last millisecond of 9999'],
        [{ address: wallet.address, account: mainnet[0], nonce: nonceOf(4).slice(1), issuedAtMs: issued }, 'a short nonce'],
        [{ address: wallet.address, account: mainnet[0], nonce: nonceOf(4).toUpperCase(), issuedAtMs: issued }, 'a nonce in capitals'],
        [{ address: wallet.address, account: mainnet[0].toUpperCase(), nonce: nonceOf(4), issuedAtMs: issued }, 'an account in capitals'],
        [{ address: legacyKey('this is a top secret passphrase').address, account: mainnet[0], nonce: nonceOf(4), issuedAtMs: issued }, 'a devnet address'],
        [{ address: otherByte, account: mainnet[0], nonce: nonceOf(4), issuedAtMs: issued }, 'an S address of network byte 62'],
    ];
    for (const [input, name] of builds) {
        const message = Proof.compose({ address: input.address, account: input.account, nonce: input.nonce, issuedAt: iso(input.issuedAtMs) });
        try {
            Proof.parse(message, {}, input.issuedAtMs);
            records.push(record('proof.build', name, input, { message }));
        } catch (error) {
            refused('proof.build', name, input, error);
        }
    }
    const walletProof = [
        'IceRoot migration ownership proof', 'Version: 1', 'Source network: solar-mainnet', `Source address: ${wallet.address}`,
        `IceRoot account: ${walletAccount}`, `Nonce: ${'7e'.repeat(32)}`, 'Issued at: 2026-09-01T12:00:00.000Z',
        'Statement: I control the source address above and ask for its holding to be bound to the IceRoot account above.',
        'No transaction or transfer is authorized.',
    ].join('\n');
    check(records.find((r) => r.name === "the legacy signer's fixed proof").output.message === walletProof, "the legacy signer's fixed proof");

    // proof.parse: the legacy signer's parse, at the reader's time.
    const base = compose();
    const now = issued + 1000;
    const replaceLine = (message, index, line) => message.split('\n').map((l, i) => (i === index ? line : l)).join('\n');
    const swapped = (() => {
        const lines = base.split('\n');
        [lines[4], lines[5]] = [lines[5], lines[4]];
        return lines.join('\n');
    })();
    const at = (text) => compose({ issuedAt: text });
    const parses = [
        [base, {}, now, 'valid'],
        [base, { address: wallet.address }, now, 'valid, address expected'],
        [compose({ account: testnet[0] }), {}, now, 'testnet account'],
        [at('2026-09-01T12:00:00Z'), {}, now, 'issued without milliseconds'],
        [walletProof, { address: wallet.address }, issued, "the legacy signer's fixed proof"],
        [base, {}, issued - 300000, 'issued five minutes ahead'],
        [base, {}, issued - 300001, 'issued more than five minutes ahead'],
        [base, {}, issued + 365 * 86400000, 'issued a year ago'],
        [base, { address: other.address }, now, 'another address expected'],
        [`${base}\n`, {}, now, 'trailing newline'],
        [base.replace(/\n/g, '\r\n'), {}, now, 'CRLF'],
        [base.split('\n').slice(0, 8).join('\n'), {}, now, 'eight lines'],
        [`${base}\nP.S.`, {}, now, 'ten lines'],
        [replaceLine(base, 0, 'Iceroot migration ownership proof'), {}, now, 'title changed'],
        [replaceLine(base, 1, 'Version: 2'), {}, now, 'version 2'],
        [replaceLine(base, 7, 'Statement: I control the source address above.'), {}, now, 'statement changed'],
        [replaceLine(base, 8, 'A transfer is authorized.'), {}, now, 'closing line changed'],
        [base.replace('Nonce: ', 'Nonce:'), {}, now, 'field without its space'],
        [swapped, {}, now, 'account and nonce lines swapped'],
        [compose().replace('solar-mainnet', 'solar-testnet'), {}, now, 'Solar testnet'],
        [compose({ address: `s${wallet.address.slice(1)}` }), {}, now, 'address in lowercase s'],
        [compose({ address: legacyKey('this is a top secret passphrase').address }), {}, now, 'a devnet address'],
        [compose({ address: badChecksum }), {}, now, 'address with a bad checksum'],
        [compose({ address: otherByte }), {}, now, 'an S address of network byte 62'],
        [compose({ address: `${wallet.address.slice(0, 20)}0${wallet.address.slice(21)}` }), {}, now, 'address with a 0'],
        [compose({ address: wallet.address.slice(0, 33) }), {}, now, '33-character address'],
        [compose({ account: mainnet[0].toUpperCase() }), {}, now, 'account in capitals'],
        [compose({ account: typo }), {}, now, 'account with one character changed'],
        [compose({ account: bech32.encode('ice', bech32m.toWords(hashOf('account 0'))) }), {}, now, 'account with a Bech32 checksum'],
        [compose({ account: bech32m.encode('ice', spareWords) }), {}, now, 'account with spare bits set'],
        [compose({ account: ` ${mainnet[0]}` }), {}, now, 'account after two spaces'],
        [compose({ nonce: nonceOf(0).toUpperCase() }), {}, now, 'nonce in capitals'],
        [compose({ nonce: nonceOf(0).slice(2) }), {}, now, '62-digit nonce'],
        [compose({ nonce: `g${nonceOf(0).slice(1)}` }), {}, now, 'nonce with a g'],
        [at('2026-09-01T12:00:00+00:00'), {}, now, 'issued with an offset'],
        [at('2026-09-01T12:00:00.00Z'), {}, now, 'issued with two digits of milliseconds'],
        [at('2026-09-01T12:00:00.000000Z'), {}, now, 'issued with microseconds'],
        [at('2026-09-01T12:00:00'), {}, now, 'issued without a zone'],
        [at('2026-09-01 12:00:00Z'), {}, now, 'issued with a space'],
        [at('2026-02-30T12:00:00Z'), {}, now, 'issued on 30 February'],
        [at('2027-02-29T12:00:00Z'), {}, Date.parse('2027-03-01T12:00:00Z'), 'issued on 29 February of a common year'],
        [at('2028-02-29T12:00:00Z'), {}, Date.parse('2028-02-29T12:00:00Z'), 'issued on 29 February of a leap year'],
        [at('2026-08-31T24:00:00Z'), {}, now, 'issued at 24:00:00'],
        [at('2026-13-01T12:00:00Z'), {}, now, 'issued in month 13'],
        [at('0000-01-01T00:00:00Z'), {}, now, 'issued in the year 0'],
        [at('yesterday'), {}, now, 'not a time'],
        [replaceLine(base, 7, 'Statement: I control the source address above and ask for its holding to be bound to the IceRoot account above. é'), {}, now, 'a character outside ASCII'],
        [replaceLine(base, 8, 'No transaction\tor transfer is authorized.'), {}, now, 'a tab'],
        [`${base}${' '.repeat(1024 - base.length + 1)}`, {}, now, 'over 1024 characters'],
        ['', {}, now, 'empty'],
        ['IceRoot Validator Portal sign-in\nVersion: 1\nNo transaction or transfer is authorized.', {}, now, 'a sign-in message'],
        [`Transfer 1000 SXP to S${'1'.repeat(33)}`, {}, now, 'a transfer'],
    ];
    for (const [message, expected, time, name] of parses) {
        const input = { message, expected, now: time };
        try {
            const fields = Proof.parse(message, expected, time);
            records.push(record('proof.parse', name, input, {
                network: fields.network,
                address: fields.address,
                account: fields.account,
                accountNetwork: fields.accountNetwork,
                nonce: fields.nonce,
                issuedAt: fields.issuedAt,
                issuedAtMs: Date.parse(fields.issuedAt),
            }));
        } catch (error) {
            refused('proof.parse', name, input, error);
        }
    }

    // proof.sign: the sandbox signs as the legacy signer does (fresh aux) and checks its own
    // signature; the record holds the reference's signature of the same digest with the fixed aux.
    const signed = [];
    const signs = [];
    keys.forEach((key, index) => {
        signs.push([key, compose({ address: key.address, account: mainnet[index % 2], nonce: nonceOf(`sign ${index}`) }), now, `key ${index}, mainnet account`]);
        signs.push([key, compose({ address: key.address, account: testnet[index % 2], nonce: nonceOf(`sign t${index}`), issuedAt: '2026-09-01T12:00:00Z' }), now, `key ${index}, testnet account`]);
    });
    signs.push([wallet, walletProof, issued, "the legacy signer's fixed proof"]);
    signs.push([other, base, now, "a message naming another key's address"]);
    signs.push([wallet, base, issued - 300001, 'issued more than five minutes ahead']);
    signs.push([wallet, 'IceRoot Validator Portal sign-in\nVersion: 1\nNo transaction or transfer is authorized.', now, 'a sign-in message']);
    for (const [key, message, time, name] of signs) {
        const input = { passphrase: key.passphrase, message, now: time, aux: hex(aux) };
        let fromSandbox;
        try {
            fromSandbox = call('signProof', { phrase: key.passphrase, message }, time);
        } catch (error) {
            refused('proof.sign', name, input, error);
            continue;
        }
        check(fromSandbox.publicKey === key.publicKey, `the sandbox signs with the key: ${name}`);
        check(reference.Crypto.Message.verify({ message, publicKey: key.publicKey, signature: fromSandbox.signature }), `the sandbox's signature verifies: ${name}`);
        const signature = reference.Crypto.Hash.signSchnorr(reference.Crypto.HashAlgorithms.sha256(message), key.keys, true, aux);
        check(call('verifyProof', { message, publicKey: key.publicKey, signature }, time) === true, `the sandbox accepts the fixed-aux signature: ${name}`);
        const proof = {
            type: Proof.TYPE, version: 1, network: Proof.NETWORK, address: key.address,
            publicKey: key.publicKey, algorithm: Proof.ALGORITHM, message, signature,
        };
        signed.push({ proof, now: time, name });
        records.push(record('proof.sign', name, input, { proof, json: JSON.stringify(proof) }));
    }

    // proof.verify: the documented verification. The signed proof's constant fields and its
    // address (step 1, with the legacy signer's parse), then the sandbox's check of a signature
    // made elsewhere (steps 1 to 3: the message, the address of the public key and the signature).
    const verifyDocumented = (proof, time) => {
        if (proof.type !== Proof.TYPE || proof.version !== 1 || proof.network !== Proof.NETWORK || proof.algorithm !== Proof.ALGORITHM) {
            return false;
        }
        try {
            Proof.parse(proof.message, { address: proof.address }, time);
            return call('verifyProof', { message: proof.message, publicKey: proof.publicKey, signature: proof.signature }, time) === true;
        } catch (error) {
            return false;
        }
    };
    const first = signed[0];
    const flip = (text) => text.slice(0, -1) + (text.endsWith('0') ? '1' : '0');
    const flipPrefix = (key) => (key.startsWith('02') ? '03' : '02') + key.slice(2);
    const otherAux = reference.Crypto.Hash.signSchnorr(reference.Crypto.HashAlgorithms.sha256(first.proof.message), wallet.keys, true, hashOf('aux verify'));
    const forged = reference.Crypto.Hash.signSchnorr(reference.Crypto.HashAlgorithms.sha256(walletProof), other.keys, true, aux);
    const invalidKey = `02${'00'.repeat(32)}`;
    // Address.fromPublicKey refuses such a key, so its address is built from the same parts.
    check(!reference.Identities.PublicKey.verify(invalidKey), 'a key that is not on the curve');
    const invalidKeyAddress = reference.Identities.Address.fromBuffer(
        Buffer.concat([Buffer.from([SOLAR_MAINNET]), reference.Crypto.HashAlgorithms.ripemd160(Buffer.from(invalidKey, 'hex'))]),
    );
    const invalidKeyMessage = compose({ address: invalidKeyAddress });
    const byOther = reference.Crypto.Hash.signSchnorr(reference.Crypto.HashAlgorithms.sha256(first.proof.message), other.keys, true, aux);
    const change = (fields) => ({ ...first.proof, ...fields });
    const verifies = [
        ...signed.map(({ proof, now: time, name }) => [proof, time, name]),
        [change({ signature: otherAux }), first.now, 'a signature with another aux'],
        [change({ message: first.proof.message.replace('Nonce: ', 'Nonce: 0').replace(/(Nonce: [0-9a-f]{64})[0-9a-f]/, '$1') }), first.now, 'message changed'],
        [change({ address: other.address }), first.now, "another key's address"],
        [change({ publicKey: other.publicKey }), first.now, "another key's public key"],
        [change({ publicKey: other.publicKey, signature: byOther }), first.now, "another key's public key and signature"],
        [change({ publicKey: first.proof.publicKey.toUpperCase() }), first.now, 'public key in capitals'],
        [change({ publicKey: flipPrefix(first.proof.publicKey) }), first.now, 'public key prefix changed'],
        [change({ signature: first.proof.signature.toUpperCase() }), first.now, 'signature in capitals'],
        [change({ signature: flip(first.proof.signature) }), first.now, 'signature changed'],
        [change({ signature: first.proof.signature.slice(2) }), first.now, '63-byte signature'],
        [change({ type: 'iceroot-ownership-proof' }), first.now, 'another type'],
        [change({ version: 2 }), first.now, 'version 2'],
        [change({ version: '1' }), first.now, 'version as a string'],
        [change({ network: 'solar-testnet' }), first.now, 'another network'],
        [change({ algorithm: 'ml-dsa-65' }), first.now, 'another algorithm'],
        [first.proof, issued - 300001, 'read more than five minutes before it was issued'],
        [first.proof, issued - 300000, 'read five minutes before it was issued'],
        [{ ...first.proof, address: wallet.address, message: walletProof, signature: forged }, issued, "a signature by another key, as from a wrong Ledger"],
        [{ ...first.proof, address: invalidKeyAddress, publicKey: invalidKey, message: invalidKeyMessage, signature: first.proof.signature }, now, 'a public key that is not on the curve'],
    ];
    for (const [proof, time, name] of verifies) {
        records.push(record('proof.verify', name, { proof, now: time }, { valid: verifyDocumented(proof, time) }));
    }
    check(records.filter((r) => r.op === 'proof.verify' && r.output.valid).length >= signed.length + 2, 'the valid proofs verify');

    write('S08-ownership-proofs', records, {
        aux: hex(aux),
        sourceNetworkByte: SOLAR_MAINNET,
        legacySignerSha256: hashes,
        scureBase: basePackage.version,
    });
}

fs.mkdirSync(outDir, { recursive: true });
phrases();
derivation();
messages();
signIn();
transactions();
feeFloors();
ownershipProofs();

// MANIFEST.sha256, in the format of sha256sum, over every vector file.
const manifest = fs
    .readdirSync(outDir)
    .filter((file) => file.endsWith('.jsonl'))
    .sort()
    .map((file) => `${hex(sha256(fs.readFileSync(path.join(outDir, file))))}  ${file}`);
fs.writeFileSync(path.join(outDir, 'MANIFEST.sha256'), manifest.join('\n') + '\n');
