#!/usr/bin/env node
// gen-keystore-vectors.js: generate the keystore vectors (vectors/sdk/S07-keystore.jsonl) with an
// independent implementation of the format as the oracle.
//
//   node tools/oracle/gen-keystore-vectors.js <packages dir> [out dir]
//
// <packages dir> holds node_modules/@noble/hashes and node_modules/@noble/ciphers (Argon2id and
// XChaCha20-Poly1305 in JavaScript, independent of the RustCrypto crates the SDK uses):
//
//   npm install --prefix <packages dir> @noble/hashes@2.4.0 @noble/ciphers@2.4.0
//
// This script writes the format of docs/keystore-format.md from that description alone: the
// header, the NFKD password, the key derivation, the sealing, the text armor, and the order of the
// checks a reader makes, with the verdict of every refusal. The output is deterministic: salts,
// nonces and secrets come from SHA-256 of fixed labels, and running it again gives the same file.
//
// Most vectors use parameters far below the format's floor, so that they run in milliseconds;
// their records name the bounds "test" (Bounds::TEST, the crate's `test-params` feature: the floor
// lowered to Argon2's own minimums, the ceilings unchanged). Records with the bounds "standard"
// use the format's real bounds, including one keystore at the floor that is fully derived.
//
// The file is in the heartwood-vectors/1 record format: a meta record, then one record per case,
// {"op", "network", "height", "name", "input", "output"} or the same with "error" in place of
// "output". A keystore belongs to no network, so every record has network "any" and height 0.
// Errors carry the SDK's error code as "class" and its structured details as "details".

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const [packagesDir, outArg] = process.argv.slice(2);
if (!packagesDir) {
    console.error('usage: gen-keystore-vectors.js <packages dir> [out dir]');
    process.exit(2);
}
const outDir = outArg || path.join(__dirname, '..', '..', 'vectors', 'sdk');
const CLASS = 'S07-keystore';

// The format ------------------------------------------------------------------------------------

const MAGIC = Buffer.from('IRKS', 'ascii');
const VERSION = 1;
const KDF_ARGON2ID = 1;
const SALT_LEN = 16;
const NONCE_LEN = 24;
const TAG_LEN = 16;
const HEADER_LEN = 60;
const MAX_PASSWORD_BYTES = 1024;
const ARMOR_PREFIX = 'irks:';
const MAX_DECODED_LEN = 1024;

const KINDS = {
    1: { name: 'bip39-entropy', lengths: [24, 28, 32], supported: true },
    2: { name: 'ml-dsa-65-seed', lengths: [32], supported: false },
};
const KIND_CODES = { 'bip39-entropy': 1, 'ml-dsa-65-seed': 2 };

const BOUNDS = {
    standard: {
        floor: { memoryKib: 19456, iterations: 2, parallelism: 1 },
        ceiling: { memoryKib: 524288, iterations: 16, parallelism: 16 },
        maxWork: 2097152,
    },
    test: {
        floor: { memoryKib: 8, iterations: 1, parallelism: 1 },
        ceiling: { memoryKib: 524288, iterations: 16, parallelism: 16 },
        maxWork: 2097152,
    },
};

class KeystoreError extends Error {
    constructor(cls, message, details = {}) {
        super(message);
        this.cls = cls;
        this.details = details;
    }
}

const malformed = (reason, message) => new KeystoreError('Malformed', message, { reason });

function encodeHeader(h) {
    const out = Buffer.alloc(HEADER_LEN);
    MAGIC.copy(out, 0);
    out[4] = h.version ?? VERSION;
    out[5] = h.kdf ?? KDF_ARGON2ID;
    out.writeUInt32BE(h.params.memoryKib, 6);
    out.writeUInt32BE(h.params.iterations, 10);
    out.writeUInt32BE(h.params.parallelism, 14);
    Buffer.from(h.salt).copy(out, 18);
    Buffer.from(h.nonce).copy(out, 34);
    out[58] = h.kind;
    out[59] = h.payloadLength;
    return out;
}

// The reader's checks, in the order the format fixes.
function parse(bytes) {
    if (bytes.length < 4 || !bytes.subarray(0, 4).equals(MAGIC)) {
        throw malformed('magic', 'it does not start with the keystore magic');
    }
    if (bytes.length < 5) {
        throw malformed('truncated', 'it ends early');
    }
    if (bytes[4] !== VERSION) {
        throw new KeystoreError('UnsupportedVersion', `format version ${bytes[4]} is not supported`, {
            version: bytes[4],
        });
    }
    if (bytes.length < HEADER_LEN + TAG_LEN) {
        throw malformed('truncated', 'it ends early');
    }
    if (bytes[5] !== KDF_ARGON2ID) {
        throw new KeystoreError('UnsupportedKdf', `key derivation function ${bytes[5]} is not supported`, {
            kdf: bytes[5],
        });
    }
    const kind = bytes[58];
    if (!(kind in KINDS)) {
        throw new KeystoreError('UnsupportedPayload', `payload kind ${kind} is not supported`, { kind });
    }
    const payloadLength = bytes[59];
    if (!KINDS[kind].lengths.includes(payloadLength)) {
        throw malformed('payload-length', 'the payload length does not fit the payload kind');
    }
    if (bytes.length !== HEADER_LEN + payloadLength + TAG_LEN) {
        throw malformed('length', 'its length does not match its header');
    }
    return {
        params: {
            memoryKib: bytes.readUInt32BE(6),
            iterations: bytes.readUInt32BE(10),
            parallelism: bytes.readUInt32BE(14),
        },
        salt: bytes.subarray(18, 34),
        nonce: bytes.subarray(34, 58),
        kind,
        payloadLength,
        aad: bytes.subarray(0, HEADER_LEN),
        sealed: bytes.subarray(HEADER_LEN),
    };
}

function checkBounds(params, bounds) {
    const range = (param, value, minimum, maximum) => {
        if (value < minimum || value > maximum) {
            throw new KeystoreError('ParamsOutOfRange', `${param} ${value} is outside ${minimum} to ${maximum}`, {
                param,
                value,
                minimum,
                maximum,
            });
        }
    };
    const { floor, ceiling, maxWork } = BOUNDS[bounds];
    range('parallelism', params.parallelism, floor.parallelism, ceiling.parallelism);
    range('memory', params.memoryKib, Math.max(floor.memoryKib, 8 * params.parallelism), ceiling.memoryKib);
    range('iterations', params.iterations, floor.iterations, ceiling.iterations);
    range('work', params.memoryKib * params.iterations, floor.memoryKib * floor.iterations, maxWork);
}

function passwordBytes(password) {
    if (password.length === 0) {
        throw new KeystoreError('InvalidPassword', 'the password is empty', { reason: 'empty' });
    }
    const raw = Buffer.from(password, 'utf8');
    if (raw.length > MAX_PASSWORD_BYTES) {
        throw new KeystoreError('InvalidPassword', 'the password is too long', {
            reason: 'too-long',
            bytes: raw.length,
            maximum: MAX_PASSWORD_BYTES,
        });
    }
    return Buffer.from(password.normalize('NFKD'), 'utf8');
}

let argon2id;
let xchacha20poly1305;

function deriveKey(password, salt, params) {
    return argon2id(password, salt, {
        t: params.iterations,
        m: params.memoryKib,
        p: params.parallelism,
        dkLen: 32,
        version: 0x13,
    });
}

function encrypt({ kind, secret, password, params, salt, nonce, bounds }) {
    const code = KIND_CODES[kind];
    if (!KINDS[code].supported) {
        throw new KeystoreError('UnsupportedPayload', `payload kind ${code} is not supported`, { kind: code });
    }
    if (!KINDS[code].lengths.includes(secret.length)) {
        throw new KeystoreError('InvalidPayload', `${kind} of ${secret.length} bytes`, {
            kind,
            length: secret.length,
        });
    }
    checkBounds(params, bounds);
    const pw = passwordBytes(password);
    const header = encodeHeader({ params, salt, nonce, kind: code, payloadLength: secret.length });
    const key = deriveKey(pw, salt, params);
    const sealed = xchacha20poly1305(key, nonce, header).encrypt(secret);
    return Buffer.concat([header, Buffer.from(sealed)]);
}

function decrypt(bytes, password, bounds) {
    const parsed = parse(bytes);
    if (!KINDS[parsed.kind].supported) {
        throw new KeystoreError('UnsupportedPayload', `payload kind ${parsed.kind} is not supported`, {
            kind: parsed.kind,
        });
    }
    checkBounds(parsed.params, bounds);
    const pw = passwordBytes(password);
    const key = deriveKey(pw, parsed.salt, parsed.params);
    let secret;
    try {
        secret = xchacha20poly1305(key, parsed.nonce, parsed.aad).decrypt(parsed.sealed);
    } catch {
        throw new KeystoreError('WrongPasswordOrCorrupt', 'wrong password, or the keystore was changed or damaged');
    }
    return { kind: KINDS[parsed.kind].name, secret: Buffer.from(secret) };
}

function armor(bytes) {
    return ARMOR_PREFIX + Buffer.from(bytes).toString('base64url');
}

function dearmor(text) {
    if (!text.startsWith(ARMOR_PREFIX)) {
        throw malformed('armor-prefix', 'the text does not start with the keystore prefix');
    }
    const encoded = text.slice(ARMOR_PREFIX.length);
    if (encoded.length > Math.ceil(MAX_DECODED_LEN / 3) * 4) {
        throw malformed('armor-length', 'the text is longer than any keystore');
    }
    // Node's decoder is lenient; the canonical form is the one its encoder writes back.
    const bytes = Buffer.from(encoded, 'base64url');
    if (!/^[A-Za-z0-9_-]*$/.test(encoded) || encoded.length % 4 === 1 || bytes.toString('base64url') !== encoded) {
        throw malformed('armor-encoding', 'the text is not canonical unpadded base64url');
    }
    return bytes;
}

// Data ------------------------------------------------------------------------------------------

const sha256 = (label) => crypto.createHash('sha256').update(label).digest();
const bytesOf = (label, length) => {
    const out = Buffer.alloc(length);
    for (let i = 0, block = 0; i < length; block++) {
        const chunk = sha256(`${label}/${block}`);
        chunk.copy(out, i, 0, Math.min(32, length - i));
        i += 32;
    }
    return out;
};
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const clone = (bytes) => Buffer.from(bytes);

function check(condition, message) {
    if (!condition) {
        throw new Error(`self-check failed: ${message}`);
    }
}

const records = [];
const record = (op, name, input, outcome) => {
    const base = { op, network: 'any', height: 0, name, input };
    if (outcome instanceof KeystoreError) {
        records.push({ ...base, error: { class: outcome.cls, message: outcome.message, details: outcome.details } });
    } else {
        records.push({ ...base, output: outcome });
    }
};
const attempt = (f) => {
    try {
        return f();
    } catch (e) {
        if (e instanceof KeystoreError) {
            return e;
        }
        throw e;
    }
};

const paramsJson = (p) => ({ memoryKib: p.memoryKib, iterations: p.iterations, parallelism: p.parallelism });
const headerJson = (bytes) => {
    const h = parse(bytes);
    return {
        version: VERSION,
        kdf: 'argon2id',
        ...paramsJson(h.params),
        salt: hex(h.salt),
        nonce: hex(h.nonce),
        payloadKind: KINDS[h.kind].name,
        payloadLength: h.payloadLength,
        keystoreLength: bytes.length,
    };
};
const openedJson = (opened) => ({
    kind: opened.kind,
    secret: hex(opened.secret),
    ...(opened.kind === 'bip39-entropy' ? { wordCount: (opened.secret.length * 3) / 4 } : {}),
});

// Cases -----------------------------------------------------------------------------------------

const P_SMALL = { memoryKib: 32, iterations: 1, parallelism: 1 };
const P_TWO = { memoryKib: 64, iterations: 2, parallelism: 2 };
const P_FOUR = { memoryKib: 256, iterations: 3, parallelism: 4 };
const P_FLOOR = { memoryKib: 19456, iterations: 2, parallelism: 1 };

const ASCII = 'correct horse battery staple';
const NFC = 'pässwörd Ångström';
const NFD = NFC.normalize('NFD');
const LIGATURE = 'ﬁre ① Ａ'; // NFKD: "fire 1 A"
const CJK = '密码 パスワード 🔑';
const LONGEST = 'k'.repeat(MAX_PASSWORD_BYTES);

function encryptCase(name, spec) {
    const input = {
        kind: spec.kind ?? 'bip39-entropy',
        secret: spec.secret,
        password: spec.password,
        params: spec.params,
        salt: bytesOf(`salt/${name}`, SALT_LEN),
        nonce: bytesOf(`nonce/${name}`, NONCE_LEN),
        bounds: spec.bounds ?? 'test',
    };
    const outcome = attempt(() => encrypt(input));
    const jsonInput = {
        kind: input.kind,
        secret: hex(input.secret),
        password: input.password,
        params: paramsJson(input.params),
        salt: hex(input.salt),
        nonce: hex(input.nonce),
        bounds: input.bounds,
    };
    if (outcome instanceof KeystoreError) {
        record('keystore.encrypt', name, jsonInput, outcome);
        return undefined;
    }
    record('keystore.encrypt', name, jsonInput, { keystore: hex(outcome), text: armor(outcome) });
    // Self-check: it opens again, and its text form decodes back.
    const opened = decrypt(outcome, spec.password, input.bounds);
    check(opened.secret.equals(input.secret), `${name}: round trip`);
    check(dearmor(armor(outcome)).equals(outcome), `${name}: armor round trip`);
    return { bytes: outcome, input };
}

function decryptCase(name, bytes, password, bounds, extra = {}) {
    const outcome = attempt(() => decrypt(bytes, password, bounds));
    record(
        'keystore.decrypt',
        name,
        { keystore: hex(bytes), password, bounds, ...extra },
        outcome instanceof KeystoreError ? outcome : openedJson(outcome),
    );
    return outcome;
}

function inspectCase(name, bytes) {
    const outcome = attempt(() => headerJson(bytes));
    record('keystore.inspect', name, { keystore: hex(bytes) }, outcome);
    return outcome;
}

function dearmorCase(name, text) {
    const outcome = attempt(() => dearmor(text));
    record('keystore.dearmor', name, { text }, outcome instanceof KeystoreError ? outcome : { keystore: hex(outcome) });
    return outcome;
}

function boundsCase(name, params, bounds) {
    const outcome = attempt(() => {
        checkBounds(params, bounds);
        return { ok: true };
    });
    record('keystore.checkParams', name, { params: paramsJson(params), bounds }, outcome);
}

async function main() {
    // Both modules sit at the root of their packages, next to package.json.
    const resolve = (name) => require.resolve(name, { paths: [packagesDir] });
    const argonModule = resolve('@noble/hashes/argon2.js');
    const chachaModule = resolve('@noble/ciphers/chacha.js');
    ({ argon2id } = await import(pathToFileURL(argonModule).href));
    ({ xchacha20poly1305 } = await import(pathToFileURL(chachaModule).href));
    const version = (module) =>
        JSON.parse(fs.readFileSync(path.join(path.dirname(module), 'package.json'), 'utf8')).version;

    const E24 = bytesOf('entropy/24', 24);
    const E28 = bytesOf('entropy/28', 28);
    const E32 = bytesOf('entropy/32', 32);

    // Encrypt, with fixed salts and nonces.
    const k24 = encryptCase('18 words, ascii password', { secret: E24, password: ASCII, params: P_SMALL });
    const k28 = encryptCase('21 words, two lanes', { secret: E28, password: ASCII, params: P_TWO });
    const k32 = encryptCase('24 words, four lanes', { secret: E32, password: ASCII, params: P_FOUR });
    const kNfc = encryptCase('24 words, accented password (NFC)', { secret: E32, password: NFC, params: P_SMALL });
    const kLig = encryptCase('24 words, compatibility characters', { secret: E32, password: LIGATURE, params: P_SMALL });
    const kCjk = encryptCase('24 words, CJK and emoji password', { secret: E32, password: CJK, params: P_SMALL });
    const kLong = encryptCase('24 words, longest password', { secret: E32, password: LONGEST, params: P_SMALL });
    const kFloor = encryptCase('24 words, at the standard floor', {
        secret: E32,
        password: ASCII,
        params: P_FLOOR,
        bounds: 'standard',
    });

    // Encrypt refusals.
    encryptCase('12 words refused', { secret: bytesOf('entropy/16', 16), password: ASCII, params: P_SMALL });
    encryptCase('15 words refused', { secret: bytesOf('entropy/20', 20), password: ASCII, params: P_SMALL });
    encryptCase('33 bytes refused', { secret: bytesOf('entropy/33', 33), password: ASCII, params: P_SMALL });
    encryptCase('reserved ML-DSA-65 seed kind', {
        kind: 'ml-dsa-65-seed',
        secret: bytesOf('xi', 32),
        password: ASCII,
        params: P_SMALL,
    });
    encryptCase('empty password', { secret: E32, password: '', params: P_SMALL });
    encryptCase('password one byte too long', { secret: E32, password: `${LONGEST}k`, params: P_SMALL });
    encryptCase('test parameters under the standard bounds', {
        secret: E32,
        password: ASCII,
        params: P_SMALL,
        bounds: 'standard',
    });
    encryptCase('memory above the ceiling', {
        secret: E32,
        password: ASCII,
        params: { memoryKib: 524289, iterations: 1, parallelism: 1 },
    });

    // Decrypt.
    decryptCase('18 words', k24.bytes, ASCII, 'test');
    decryptCase('21 words', k28.bytes, ASCII, 'test');
    decryptCase('24 words', k32.bytes, ASCII, 'test');
    decryptCase('accented password typed in NFC', kNfc.bytes, NFC, 'test');
    decryptCase('accented password typed in NFD', kNfc.bytes, NFD, 'test');
    decryptCase('compatibility characters', kLig.bytes, LIGATURE, 'test');
    decryptCase('compatibility characters typed decomposed', kLig.bytes, LIGATURE.normalize('NFKD'), 'test');
    decryptCase('CJK and emoji password', kCjk.bytes, CJK, 'test');
    decryptCase('longest password', kLong.bytes, LONGEST, 'test');
    decryptCase('at the standard floor', kFloor.bytes, ASCII, 'standard');
    decryptCase('wrong password', k32.bytes, 'correct horse battery stapler', 'test');
    decryptCase('wrong password, case', k32.bytes, ASCII.toUpperCase(), 'test');
    decryptCase('wrong password at the standard floor', kFloor.bytes, 'Correct horse battery staple', 'standard');
    decryptCase('empty password', k32.bytes, '', 'test');
    decryptCase('password too long', k32.bytes, `${LONGEST}k`, 'test');
    decryptCase('test parameters refused by the standard floor', k32.bytes, ASCII, 'standard');

    // Tampering: every header field, the ciphertext and the tag of the 24-word keystore.
    const base = k32.bytes;
    const tamper = (name, field, edit, password = ASCII) => {
        const bytes = clone(base);
        const result = edit(bytes) ?? bytes;
        const outcome = decryptCase(`tampered ${name}`, result, password, 'test', { tampered: field });
        check(outcome instanceof KeystoreError, `tampered ${name} must fail`);
        return result;
    };
    const setU32 = (offset, value) => (b) => {
        b.writeUInt32BE(value, offset);
    };
    const xor = (offset, mask = 0x01) => (b) => {
        b[offset] ^= mask;
    };
    tamper('magic, first byte', 'magic', xor(0));
    tamper('magic, last byte', 'magic', xor(3));
    tamper('version 0', 'version', (b) => {
        b[4] = 0;
    });
    tamper('version 2', 'version', (b) => {
        b[4] = 2;
    });
    tamper('version 255', 'version', (b) => {
        b[4] = 255;
    });
    tamper('kdf 0', 'kdf', (b) => {
        b[5] = 0;
    });
    tamper('kdf 2', 'kdf', (b) => {
        b[5] = 2;
    });
    tamper('memory, in range', 'memory', setU32(6, 257));
    tamper('memory, lowest byte', 'memory', xor(9, 0x80));
    tamper('memory, highest byte, over the ceiling', 'memory', xor(6));
    tamper('iterations, in range, one more', 'iterations', setU32(10, 4));
    tamper('iterations, in range, one fewer', 'iterations', setU32(10, 2));
    tamper('iterations, zero', 'iterations', setU32(10, 0));
    tamper('iterations, highest byte', 'iterations', xor(10));
    tamper('parallelism, in range', 'parallelism', setU32(14, 3));
    tamper('parallelism, zero', 'parallelism', setU32(14, 0));
    tamper('parallelism, over the ceiling', 'parallelism', setU32(14, 17));
    tamper('salt, first byte', 'salt', xor(18));
    tamper('salt, last byte', 'salt', xor(33));
    tamper('nonce, first byte', 'nonce', xor(34));
    tamper('nonce, last byte', 'nonce', xor(57));
    const reservedKind = tamper('payload kind, the reserved kind', 'payloadKind', (b) => {
        b[58] = 2;
    });
    tamper('payload kind 0', 'payloadKind', (b) => {
        b[58] = 0;
    });
    tamper('payload kind 3', 'payloadKind', (b) => {
        b[58] = 3;
    });
    tamper('payload length, 28 of 32 bytes', 'payloadLength', (b) => {
        b[59] = 28;
    });
    tamper('payload length, 16', 'payloadLength', (b) => {
        b[59] = 16;
    });
    tamper('payload length, 33', 'payloadLength', (b) => {
        b[59] = 33;
    });
    tamper('payload length 28, ciphertext shortened to match', 'payloadLength', (b) => {
        b[59] = 28;
        return Buffer.concat([b.subarray(0, HEADER_LEN + 28), b.subarray(HEADER_LEN + 32)]);
    });
    tamper('ciphertext, first byte', 'ciphertext', xor(HEADER_LEN));
    tamper('ciphertext, last byte', 'ciphertext', xor(HEADER_LEN + 31));
    tamper('tag, first byte', 'tag', xor(HEADER_LEN + 32));
    tamper('tag, last byte', 'tag', xor(HEADER_LEN + 32 + 15, 0x80));
    tamper('one byte short', 'length', (b) => b.subarray(0, b.length - 1));
    tamper('one byte more', 'length', (b) => Buffer.concat([b, Buffer.from([0])]));
    tamper('header and tag only', 'length', (b) => b.subarray(0, HEADER_LEN + TAG_LEN));
    tamper('header only', 'length', (b) => b.subarray(0, HEADER_LEN));
    tamper('magic and version only', 'length', (b) => b.subarray(0, 5));
    tamper('magic only', 'length', (b) => b.subarray(0, 4));
    tamper('empty', 'length', () => Buffer.alloc(0));

    // Parameters out of range, under the standard bounds: well-formed keystores whose parameters
    // are refused before any derivation (their ciphertext and tag are arbitrary).
    const crafted = (name, params, bounds = 'standard') => {
        const header = encodeHeader({
            params,
            salt: bytesOf(`salt/${name}`, SALT_LEN),
            nonce: bytesOf(`nonce/${name}`, NONCE_LEN),
            kind: 1,
            payloadLength: 32,
        });
        const bytes = Buffer.concat([header, bytesOf(`sealed/${name}`, 32 + TAG_LEN)]);
        const outcome = decryptCase(`out of range: ${name}`, bytes, ASCII, bounds);
        check(outcome instanceof KeystoreError && outcome.cls === 'ParamsOutOfRange', `${name}: out of range`);
        return bytes;
    };
    const outOfRange = crafted('memory below the floor', { memoryKib: 19455, iterations: 2, parallelism: 1 });
    crafted('memory above the ceiling', { memoryKib: 524289, iterations: 2, parallelism: 1 });
    crafted('memory 2^32 - 1', { memoryKib: 0xffffffff, iterations: 2, parallelism: 1 });
    crafted('iterations below the floor', { memoryKib: 19456, iterations: 1, parallelism: 1 });
    crafted('iterations above the ceiling', { memoryKib: 19456, iterations: 17, parallelism: 1 });
    crafted('iterations 2^32 - 1', { memoryKib: 19456, iterations: 0xffffffff, parallelism: 1 });
    crafted('parallelism zero', { memoryKib: 19456, iterations: 2, parallelism: 0 });
    crafted('parallelism above the ceiling', { memoryKib: 19456, iterations: 2, parallelism: 17 });
    crafted('parallelism 2^32 - 1', { memoryKib: 19456, iterations: 2, parallelism: 0xffffffff });
    crafted('work above the ceiling', { memoryKib: 524288, iterations: 5, parallelism: 1 });
    crafted('every parameter at the ceiling', { memoryKib: 524288, iterations: 16, parallelism: 16 });
    crafted('test bounds: memory below 8 KiB', { memoryKib: 7, iterations: 1, parallelism: 1 }, 'test');
    crafted('test bounds: memory below 8 KiB per lane', { memoryKib: 15, iterations: 1, parallelism: 2 }, 'test');
    crafted('test bounds: iterations zero', { memoryKib: 8, iterations: 0, parallelism: 1 }, 'test');

    // The bounds alone, at their edges.
    boundsCase('the standard floor', P_FLOOR, 'standard');
    boundsCase('the desktop preset', { memoryKib: 262144, iterations: 3, parallelism: 4 }, 'standard');
    boundsCase('the mobile preset', { memoryKib: 131072, iterations: 3, parallelism: 4 }, 'standard');
    boundsCase('the web preset', { memoryKib: 65536, iterations: 4, parallelism: 4 }, 'standard');
    boundsCase('memory ceiling at the largest work', { memoryKib: 524288, iterations: 4, parallelism: 16 }, 'standard');
    boundsCase('iterations ceiling', { memoryKib: 131072, iterations: 16, parallelism: 1 }, 'standard');
    boundsCase('work one KiB over', { memoryKib: 131073, iterations: 16, parallelism: 1 }, 'standard');
    boundsCase('memory one under the floor', { memoryKib: 19455, iterations: 2, parallelism: 1 }, 'standard');
    boundsCase('iterations one under the floor', { memoryKib: 65536, iterations: 1, parallelism: 1 }, 'standard');
    boundsCase('parallelism at the ceiling', { memoryKib: 19456, iterations: 2, parallelism: 16 }, 'standard');
    boundsCase('test floor', { memoryKib: 8, iterations: 1, parallelism: 1 }, 'test');
    boundsCase('test floor with two lanes', { memoryKib: 16, iterations: 1, parallelism: 2 }, 'test');

    // Inspect: the header without the password.
    inspectCase('18 words', k24.bytes);
    inspectCase('24 words, four lanes', k32.bytes);
    inspectCase('at the standard floor', kFloor.bytes);
    inspectCase('the reserved kind is read', reservedKind);
    inspectCase('parameters out of range are reported as they are', outOfRange);
    const inspectRefused = (name, edit) => {
        const bytes = clone(base);
        const result = edit(bytes) ?? bytes;
        const outcome = inspectCase(name, result);
        check(outcome instanceof KeystoreError, `${name} must fail`);
    };
    inspectRefused('version 2', (b) => {
        b[4] = 2;
    });
    inspectRefused('kdf 2', (b) => {
        b[5] = 2;
    });
    inspectRefused('payload kind 3', (b) => {
        b[58] = 3;
    });
    inspectRefused('payload length 16', (b) => {
        b[59] = 16;
    });
    inspectRefused('one byte more', (b) => Buffer.concat([b, Buffer.from([0])]));
    inspectRefused('not a keystore', () => Buffer.from('{"version":3,"crypto":{}}', 'utf8'));

    // Text form. The 18-word keystore is 100 bytes, so its text ends in a partial group whose
    // unused bits must be zero; the 24-word one is 108 bytes, a whole number of groups.
    const text24 = armor(k24.bytes);
    const text32 = armor(k32.bytes);
    check(text24.length === ARMOR_PREFIX.length + 134 && text32.length === ARMOR_PREFIX.length + 144, 'text lengths');
    dearmorCase('18 words', text24);
    dearmorCase('24 words', text32);
    decryptTextCase('decrypt from the text form', text32, ASCII);
    const body = text32.slice(ARMOR_PREFIX.length);
    dearmorCase('uppercase prefix', `IRKS:${body}`);
    dearmorCase('no prefix', body);
    dearmorCase('prefix without the colon', `irks${body}`);
    dearmorCase('padding', `${text24}==`);
    dearmorCase('standard base64 alphabet', `${ARMOR_PREFIX}+${body.slice(1)}`);
    dearmorCase('slash', `${ARMOR_PREFIX}/${body.slice(1)}`);
    dearmorCase('line break inside', `${ARMOR_PREFIX}${body.slice(0, 64)}\n${body.slice(64)}`);
    dearmorCase('trailing line break', `${text32}\n`);
    dearmorCase('space after the prefix', `${ARMOR_PREFIX} ${body}`);
    dearmorCase('one character too many', `${text32}A`);
    const last = text24[text24.length - 1];
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const index = alphabet.indexOf(last);
    check(index % 16 === 0, 'the last character of a 100-byte text has four zero bits');
    dearmorCase('unused bits set in the last character', `${text24.slice(0, -1)}${alphabet[index + 1]}`);
    dearmorCase('longer than any keystore', `${ARMOR_PREFIX}${'A'.repeat(1372)}`);
    dearmorCase('empty after the prefix', ARMOR_PREFIX);

    const file = path.join(outDir, `${CLASS}.jsonl`);
    const meta = {
        op: 'meta',
        format: 'heartwood-vectors/1',
        class: CLASS,
        records: records.length,
        generator: 'tools/oracle/gen-keystore-vectors.js',
        oracle: { '@noble/hashes': version(argonModule), '@noble/ciphers': version(chachaModule) },
        node: process.version,
        keystoreFormat: VERSION,
        bounds: BOUNDS,
    };
    const lines = [meta, ...records].map((r) => JSON.stringify(r));
    fs.writeFileSync(file, lines.join('\n') + '\n');
    console.log(`${CLASS}: ${records.length} records`);

    function decryptTextCase(name, text, password) {
        const outcome = attempt(() => decrypt(dearmor(text), password, 'test'));
        record(
            'keystore.decrypt',
            name,
            { text, password, bounds: 'test' },
            outcome instanceof KeystoreError ? outcome : openedJson(outcome),
        );
    }
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
