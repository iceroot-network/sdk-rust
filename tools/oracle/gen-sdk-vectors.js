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
// vectors. The reference needs Node 18. The output is deterministic: running it again gives the
// same files.
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

fs.mkdirSync(outDir, { recursive: true });
phrases();
derivation();
messages();
signIn();
transactions();
feeFloors();

// MANIFEST.sha256, in the format of sha256sum, over every vector file.
const manifest = fs
    .readdirSync(outDir)
    .filter((file) => file.endsWith('.jsonl'))
    .sort()
    .map((file) => `${hex(sha256(fs.readFileSync(path.join(outDir, file))))}  ${file}`);
fs.writeFileSync(path.join(outDir, 'MANIFEST.sha256'), manifest.join('\n') + '\n');
