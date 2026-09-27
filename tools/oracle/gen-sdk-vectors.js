#!/usr/bin/env node
// gen-sdk-vectors.js: generate the SDK's own vectors (vectors/sdk/) with the reference
// implementation as the oracle.
//
//   node tools/oracle/gen-sdk-vectors.js <reference checkout> <browser wallet checkout> [out dir]
//
// <reference checkout> is a built checkout of the reference implementation (its packages/crypto
// has dist/ and node_modules/): the phrases, seeds and hardened derivations come from the
// libraries it uses itself (bip39 and @scure/bip32), and the passphrase keys, addresses and
// message signatures from its crypto package. <browser wallet checkout> holds the wallet's
// signing-protocol.js, whose checks give the verdicts of the sign-in vectors. The output is
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

fs.mkdirSync(outDir, { recursive: true });
phrases();
derivation();
messages();
signIn();

// MANIFEST.sha256, in the format of sha256sum, over every vector file.
const manifest = fs
    .readdirSync(outDir)
    .filter((file) => file.endsWith('.jsonl'))
    .sort()
    .map((file) => `${hex(sha256(fs.readFileSync(path.join(outDir, file))))}  ${file}`);
fs.writeFileSync(path.join(outDir, 'MANIFEST.sha256'), manifest.join('\n') + '\n');
