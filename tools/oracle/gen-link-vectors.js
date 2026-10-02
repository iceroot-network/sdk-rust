#!/usr/bin/env node
// gen-link-vectors.js: generate the account link vectors (vectors/sdk/S09-account-links.jsonl)
// with an independent implementation of the format as the oracle.
//
//   node tools/oracle/gen-link-vectors.js <reference checkout> [out dir]
//
// <reference checkout> is a built checkout of the reference implementation (its packages/crypto
// has dist/ and node_modules/): the passphrase keys, addresses and message signatures come from
// its crypto package. This script writes the format of docs/account-links.md from that
// description alone: the link and revocation messages, the order of the checks a reader makes
// with the reason of every refusal, the signed record's JSON (JavaScript's JSON.stringify of the
// five members, in their order, which the SDK's TypeScript functions write too), the no-replay
// rule, and plain message signing's refusal of link text. It shares no code with the SDK. The
// output is deterministic: signatures take the fixed aux 0x42 x 32, and running it again gives
// the same file.
//
// It writes S09-account-links.jsonl into [out dir] (vectors/sdk by default) and rewrites the
// directory's MANIFEST.sha256 over every vector file in it.
//
// The file is in the heartwood-vectors/1 record format: a meta record, then one record per case,
// {"op", "network", "height", "name", "input", "output"} or the same with "error" in place of
// "output". Errors carry the SDK's error code as "class" and its structured details as "details".
// Times are in milliseconds since 1970-01-01T00:00:00Z, except a build request's issue times,
// which are in seconds as the SDK's request takes them.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const [referenceDir, outArg] = process.argv.slice(2);
if (!referenceDir) {
    console.error('usage: gen-link-vectors.js <reference checkout> [out dir]');
    process.exit(2);
}
const outDir = outArg || path.join(__dirname, '..', '..', 'vectors', 'sdk');
const reference = require(path.join(referenceDir, 'packages', 'crypto', 'dist', 'index.js'));

const CLASS = 'S09-account-links';
const NETWORK_BYTE = 90;
const NETWORK = `heartwood-devnet-v${NETWORK_BYTE}`;
const ALGORITHM = 'secp256k1-bip340-sha256';
const AUX = Buffer.alloc(32, 0x42);
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

function check(condition, message) {
    if (!condition) {
        throw new Error(`self-check failed: ${message}`);
    }
}

// ------------------------------------------------------------------------------------------------
// The format, from docs/account-links.md.

const TITLE = 'IceRoot account link';
const REVOCATION_TITLE = 'IceRoot account link revocation';
const VERSION_LINE = 'Version: 1';
const INTENT = 'Intent: Link this GitHub account and this IceRoot account as the same holder.';
const REVOCATION_INTENT = 'Intent: End the link between this GitHub account and this IceRoot account.';
const CLOSING = 'No transaction or transfer is authorized.';
const MAX_GITHUB_ID = 9007199254740991n;
const MAX_LENGTH = 4096;
const MAX_JSON_LENGTH = 16384;
const AHEAD_MS = 30000;

class Refused extends Error {
    constructor(code, reason) {
        super(`${code}: ${reason}`);
        this.code = code;
        this.reason = reason;
    }
}
const refuse = (reason) => {
    throw new Refused('InvalidLink', reason);
};

// Whole seconds since 1970 as YYYY-MM-DDTHH:MM:SSZ.
const timeText = (seconds) => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');

// Milliseconds of `text` in the form YYYY-MM-DDTHH:MM:SSZ that is a real UTC date and time, or
// null. Date.parse is not used to decide: it rolls 30 February over into March.
function readTime(text) {
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(text);
    if (!match) {
        return null;
    }
    const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
    const date = new Date(0);
    date.setUTCFullYear(year, month - 1, day);
    date.setUTCHours(hour, minute, second, 0);
    const real = date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 &&
        date.getUTCDate() === day && date.getUTCHours() === hour &&
        date.getUTCMinutes() === minute && date.getUTCSeconds() === second;
    return real ? date.getTime() : null;
}

function isValidKey(text) {
    if (!/^0[23][0-9a-f]{64}$/.test(text)) {
        return false;
    }
    try {
        return reference.Identities.PublicKey.verify(text);
    } catch {
        return false;
    }
}

const addressOf = (publicKey, byte = NETWORK_BYTE) => reference.Identities.Address.fromPublicKey(publicKey, byte);

// The checks of a reader on the network NETWORK, in the order of docs/account-links.md.
function parse(message, expected, now) {
    if (Buffer.byteLength(message, 'utf8') > MAX_LENGTH || message.includes('\r')) {
        refuse('format');
    }
    const lines = message.split('\n');
    let kind;
    if (lines.length === 9 && lines[0] === TITLE) {
        kind = 'link';
    } else if (lines.length === 10 && lines[0] === REVOCATION_TITLE) {
        kind = 'revocation';
    } else {
        refuse('format');
    }
    const intent = lines[lines.length - 2];
    if (lines[1] !== VERSION_LINE || intent !== (kind === 'link' ? INTENT : REVOCATION_INTENT) ||
        lines[lines.length - 1] !== CLOSING) {
        refuse('format');
    }
    const field = (line, label) => {
        if (!line.startsWith(label)) {
            refuse('field');
        }
        const value = line.slice(label.length);
        if (value === '' || /^[ \t]|[ \t]$/.test(value)) {
            refuse('field');
        }
        return value;
    };
    const network = field(lines[2], 'Network: ');
    const id = field(lines[3], 'GitHub user id: ');
    const account = field(lines[4], 'Account: ');
    const publicKey = field(lines[5], 'Public key: ');
    const issuedAt = field(lines[6], 'Issued at: ');
    const endsAt = kind === 'revocation' ? field(lines[7], 'Ends link issued at: ') : null;

    if (network !== NETWORK) {
        refuse('network');
    }
    if (!/^[1-9][0-9]{0,15}$/.test(id) || BigInt(id) > MAX_GITHUB_ID) {
        refuse('github-id');
    }
    if (!isValidKey(publicKey)) {
        refuse('key');
    }
    if (addressOf(publicKey) !== account) {
        refuse('address');
    }
    const issuedAtMs = readTime(issuedAt);
    if (issuedAtMs === null) {
        refuse('issued-at');
    }
    if (issuedAtMs > now + AHEAD_MS) {
        refuse('future');
    }
    let endsAtMs = null;
    if (endsAt !== null) {
        endsAtMs = readTime(endsAt);
        if (endsAtMs === null || endsAtMs >= issuedAtMs) {
            refuse('ends-link');
        }
    }
    const differs = (wanted, actual) => wanted !== undefined && wanted !== actual;
    if (differs(expected.kind, kind) || differs(expected.githubId, Number(id)) ||
        differs(expected.publicKey, publicKey) || differs(expected.address, account)) {
        refuse('mismatch');
    }
    const fields = { kind, network, githubId: Number(id), account, publicKey, issuedAt, issuedAtMs };
    if (kind === 'revocation') {
        Object.assign(fields, { endsLinkIssuedAt: endsAt, endsLinkIssuedAtMs: endsAtMs });
    }
    return fields;
}

function build(request) {
    const { kind, githubId, publicKey, issuedAt, endsLinkIssuedAt } = request;
    if (!Number.isSafeInteger(githubId) || githubId < 1) {
        refuse('github-id');
    }
    const lines = [
        kind === 'link' ? TITLE : REVOCATION_TITLE,
        VERSION_LINE,
        `Network: ${NETWORK}`,
        `GitHub user id: ${githubId}`,
        `Account: ${addressOf(publicKey)}`,
        `Public key: ${publicKey}`,
        `Issued at: ${timeText(issuedAt)}`,
    ];
    if (kind === 'revocation') {
        lines.push(`Ends link issued at: ${timeText(endsLinkIssuedAt)}`, REVOCATION_INTENT);
    } else {
        lines.push(INTENT);
    }
    lines.push(CLOSING);
    const message = lines.join('\n');
    parse(message, {}, issuedAt * 1000);
    return message;
}

// The signed record, as the TypeScript SDK writes it.
const recordJson = (record) => JSON.stringify({
    message: record.message,
    publicKey: record.publicKey,
    signature: record.signature,
    algorithm: record.algorithm,
    network: record.network,
});

function readRecord(text) {
    if (Buffer.byteLength(text, 'utf8') > MAX_JSON_LENGTH) {
        refuse('json');
    }
    let value;
    try {
        value = JSON.parse(text);
    } catch {
        refuse('json');
    }
    const members = ['message', 'publicKey', 'signature', 'algorithm', 'network'];
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).length !== members.length ||
        !members.every((key) => typeof value[key] === 'string')) {
        refuse('json');
    }
    return value;
}

const signatureOf = (message, keys, aux = AUX) =>
    reference.Crypto.Hash.signSchnorr(reference.Crypto.HashAlgorithms.sha256(message), keys, true, aux);

function verify(text, expected, now) {
    const record = readRecord(text);
    const fields = parse(record.message, expected, now);
    if (record.publicKey !== fields.publicKey || record.network !== fields.network ||
        record.algorithm !== ALGORITHM) {
        refuse('record');
    }
    if (!/^[0-9a-f]{128}$/.test(record.signature) ||
        !reference.Crypto.Message.verify({ message: record.message, publicKey: record.publicKey, signature: record.signature })) {
        refuse('signature');
    }
    return fields;
}

function sign(key, message, now) {
    const fields = parse(message, { publicKey: key.publicKey, address: key.address }, now);
    const record = { message, publicKey: key.publicKey, signature: signatureOf(message, key.keys), algorithm: ALGORITHM, network: NETWORK };
    check(reference.Crypto.Message.verify(record), 'the signature verifies');
    check(verify(recordJson(record), {}, now).issuedAtMs === fields.issuedAtMs, 'the record verifies');
    return record;
}

// The no-replay rule: entries of the same GitHub id, account and network form the barrier.
function history(message, recorded, now) {
    const fields = parse(message, {}, now);
    const same = recorded.filter((entry) => entry.network === fields.network &&
        entry.githubId === fields.githubId && entry.account === fields.account);
    if (same.some((entry) => entry.at >= fields.issuedAtMs)) {
        refuse('replay');
    }
    if (fields.kind === 'revocation' &&
        !same.some((entry) => entry.event === 'link' && entry.at === fields.endsLinkIssuedAtMs)) {
        refuse('unknown-link');
    }
    return { accepted: true };
}

// Plain message signing: text whose first line is a link's or a revocation's is refused.
const LINK_TEXT = 'an account link is signed only as a checked link, never as a plain message';
function plainSign(key, message) {
    const first = message.split('\n')[0];
    if (first === TITLE || first === REVOCATION_TITLE) {
        throw new Refused('InvalidArgument', LINK_TEXT);
    }
    return { signature: signatureOf(message, key.keys) };
}

// ------------------------------------------------------------------------------------------------
// The cases.

function legacyKey(passphrase) {
    const keys = reference.Identities.Keys.fromPassphrase(passphrase);
    const publicKey = keys.publicKey.secp256k1;
    return { passphrase, keys, publicKey, address: addressOf(publicKey) };
}

const records = [];
const record = (op, name, input, run) => {
    let result;
    try {
        result = { output: run() };
    } catch (error) {
        if (!(error instanceof Refused)) {
            throw error;
        }
        result = { error: { class: error.code, details: { reason: error.reason } } };
    }
    records.push({ op, network: 'devnet', height: 1, name, input, ...result });
    return result;
};
const expectRefusal = (result, reason, name) => check(result.error && result.error.details.reason === reason, `${name}: ${reason}, got ${JSON.stringify(result)}`);
const expectOutput = (result, name) => check(result.output !== undefined, `${name}: accepted, got ${JSON.stringify(result)}`);

const holder = legacyKey('this is a top secret passphrase');
const other = legacyKey('another top secret passphrase');
check(holder.publicKey === '034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192', 'the holder key');
check(holder.address === 'dEHxjxZybRiykTqqZUgfQoMqZZ3RxVj1dt', 'the holder address');

const ID = 9999999001;
const ISSUED = 1790426096; // 2026-09-26T12:34:56Z
const NOW = ISSUED * 1000 + 1000;
const LATER = ISSUED + 86400;

const link = build({ kind: 'link', githubId: ID, publicKey: holder.publicKey, issuedAt: ISSUED });
const revocation = build({ kind: 'revocation', githubId: ID, publicKey: holder.publicKey, issuedAt: LATER, endsLinkIssuedAt: ISSUED });
const LATER_NOW = LATER * 1000 + 1000;
const lines = (text) => text.split('\n');
const withLine = (text, index, line) => lines(text).map((old, i) => (i === index ? line : old)).join('\n');

// link.build
const buildCase = (name, request) => record('link.build', name, request, () => ({ message: build(request) }));
check(buildCase('a link', { kind: 'link', githubId: ID, publicKey: holder.publicKey, issuedAt: ISSUED }).output.message === link, 'build');
buildCase('a revocation', { kind: 'revocation', githubId: ID, publicKey: holder.publicKey, issuedAt: LATER, endsLinkIssuedAt: ISSUED });
buildCase('the largest GitHub user id', { kind: 'link', githubId: Number(MAX_GITHUB_ID), publicKey: other.publicKey, issuedAt: ISSUED });
expectRefusal(buildCase('GitHub user id 0', { kind: 'link', githubId: 0, publicKey: holder.publicKey, issuedAt: ISSUED }), 'github-id', 'build 0');
expectRefusal(buildCase('a revocation ending a link issued at the same time', { kind: 'revocation', githubId: ID, publicKey: holder.publicKey, issuedAt: ISSUED, endsLinkIssuedAt: ISSUED }), 'ends-link', 'build ends');
expectRefusal(buildCase('a revocation older than the link it names', { kind: 'revocation', githubId: ID, publicKey: holder.publicKey, issuedAt: ISSUED, endsLinkIssuedAt: LATER }), 'ends-link', 'build ends later');

// link.parse
const parseCase = (name, message, reason, { expected = {}, now = NOW } = {}) => {
    const result = record('link.parse', name, { message, expected, now }, () => parse(message, expected, now));
    if (reason) {
        expectRefusal(result, reason, name);
    } else {
        expectOutput(result, name);
    }
    return result;
};
parseCase('a link', link);
parseCase('a link, everything expected', link, null, { expected: { kind: 'link', githubId: ID, publicKey: holder.publicKey, address: holder.address } });
parseCase('a revocation', revocation, null, { now: LATER_NOW, expected: { kind: 'revocation' } });
parseCase('a link issued years ago: no expiry', link, null, { now: NOW + 5 * 365 * 86400000 });
parseCase('issued 30 seconds ahead of the clock', link, null, { now: ISSUED * 1000 - 30000 });
parseCase('issued 31 seconds ahead of the clock', link, 'future', { now: ISSUED * 1000 - 31000 });
const maxLink = build({ kind: 'link', githubId: Number(MAX_GITHUB_ID), publicKey: holder.publicKey, issuedAt: ISSUED });
parseCase('the largest GitHub user id', maxLink);
parseCase('GitHub user id 2^53', withLine(link, 3, 'GitHub user id: 9007199254740992'), 'github-id');
parseCase('GitHub user id 0', withLine(link, 3, 'GitHub user id: 0'), 'github-id');
parseCase('a GitHub user id with a leading zero', withLine(link, 3, `GitHub user id: 0${ID}`), 'github-id');
parseCase('a GitHub user id with a sign', withLine(link, 3, `GitHub user id: +${ID}`), 'github-id');
parseCase('a GitHub user id in full-width digits', withLine(link, 3, 'GitHub user id: ９９９'), 'github-id');
parseCase('a GitHub user id in hexadecimal', withLine(link, 3, 'GitHub user id: 0x2540be3f9'), 'github-id');
// Each line altered.
parseCase('the first line altered', withLine(link, 0, 'IceRoot account Link'), 'format');
parseCase('the version altered', withLine(link, 1, 'Version: 2'), 'format');
const otherNetwork = withLine(withLine(link, 2, 'Network: heartwood-devnet-v91'), 4, `Account: ${addressOf(holder.publicKey, 91)}`);
parseCase('another network, with the key\'s address there', otherNetwork, 'network');
parseCase('the network line without its space', withLine(link, 2, `Network:${NETWORK}`), 'field');
parseCase('the GitHub user id label altered', withLine(link, 3, `GitHub user ID: ${ID}`), 'field');
parseCase('another account', withLine(link, 4, `Account: ${other.address}`), 'address');
parseCase('the account label altered', withLine(link, 4, `Address: ${holder.address}`), 'field');
parseCase('another key, the account unchanged', withLine(link, 5, `Public key: ${other.publicKey}`), 'address');
parseCase('the key in capitals', withLine(link, 5, `Public key: ${holder.publicKey.toUpperCase()}`), 'key');
parseCase('a key that is not on the curve', withLine(link, 5, `Public key: 02${'ff'.repeat(32)}`), 'key');
parseCase('an uncompressed key prefix', withLine(link, 5, `Public key: 04${holder.publicKey.slice(2)}`), 'key');
parseCase('the issue time with milliseconds', withLine(link, 6, 'Issued at: 2026-09-26T12:34:56.000Z'), 'issued-at');
parseCase('the issue time with an offset', withLine(link, 6, 'Issued at: 2026-09-26T12:34:56+00:00'), 'issued-at');
parseCase('issued on 30 February', withLine(link, 6, 'Issued at: 2026-02-30T12:34:56Z'), 'issued-at');
parseCase('issued at 24:00:00', withLine(link, 6, 'Issued at: 2026-09-26T24:00:00Z'), 'issued-at');
parseCase('the intent line altered', withLine(link, 7, 'Intent: Link these accounts.'), 'format');
parseCase('the last line altered', withLine(link, 8, 'No transaction is authorized.'), 'format');
// White space and line endings.
parseCase('a newline at the end', `${link}\n`, 'format');
parseCase('CRLF line endings', link.replace(/\n/g, '\r\n'), 'format');
parseCase('a carriage return at the end', `${link}\r`, 'format');
parseCase('two spaces after a colon', withLine(link, 4, `Account:  ${holder.address}`), 'field');
parseCase('a space at the end of a field line', withLine(link, 5, `Public key: ${holder.publicKey} `), 'field');
parseCase('a tab at the end of a field line', withLine(link, 3, `GitHub user id: ${ID}\t`), 'field');
parseCase('a space at the end of a fixed line', withLine(link, 1, 'Version: 1 '), 'format');
parseCase('a space before the first line', ` ${link}`, 'format');
parseCase('a line added', `${link}\nSigned by me.`, 'format');
parseCase('a line removed', lines(link).filter((_, i) => i !== 7).join('\n'), 'format');
// Other text.
parseCase('non-ASCII: a Cyrillic letter in the first line', link.replace('IceRoot', 'IcеRoot'), 'format');
parseCase('non-ASCII: the network name', withLine(link, 2, 'Network: heartwood-devnet-v９0'), 'network');
parseCase('a 32-byte message', '0123456789abcdef0123456789abcdef', 'format');
parseCase('the empty message', '', 'format');
parseCase('a sign-in message', 'IceRoot Validator Portal sign-in\nVersion: 1', 'format');
// Revocations.
parseCase('a revocation with the link\'s intent', withLine(revocation, 8, INTENT), 'format', { now: LATER_NOW });
parseCase('a link with the revocation\'s intent', withLine(link, 7, REVOCATION_INTENT), 'format');
parseCase('a revocation without its ended link', lines(revocation).filter((_, i) => i !== 7).join('\n'), 'format', { now: LATER_NOW });
parseCase('a revocation ending a link issued at the same time', withLine(revocation, 7, `Ends link issued at: ${timeText(LATER)}`), 'ends-link', { now: LATER_NOW });
parseCase('a revocation older than the link it names', withLine(revocation, 7, `Ends link issued at: ${timeText(LATER + 60)}`), 'ends-link', { now: LATER_NOW });
parseCase('a revocation with a malformed ended link time', withLine(revocation, 7, 'Ends link issued at: 2026-09-26T12:34:56.000Z'), 'ends-link', { now: LATER_NOW });
parseCase('the ended link label altered', withLine(revocation, 7, `Ends link: ${timeText(ISSUED)}`), 'field', { now: LATER_NOW });
// What the reader expects.
parseCase('a revocation where a link is expected', revocation, 'mismatch', { now: LATER_NOW, expected: { kind: 'link' } });
parseCase('another GitHub user id expected', link, 'mismatch', { expected: { githubId: ID + 1 } });
parseCase('another key expected', link, 'mismatch', { expected: { publicKey: other.publicKey } });
parseCase('another address expected', link, 'mismatch', { expected: { address: other.address } });

// link.sign: the checked path, with the fixed aux.
const signCase = (name, key, message, now, reason) => {
    const input = { passphrase: key.passphrase, message, now, aux: hex(AUX) };
    const result = record('link.sign', name, input, () => {
        const signed = sign(key, message, now);
        return { record: signed, json: recordJson(signed) };
    });
    if (reason) {
        expectRefusal(result, reason, name);
    } else {
        expectOutput(result, name);
    }
    return result;
};
const signedLink = signCase('a link', holder, link, NOW).output;
const signedRevocation = signCase('a revocation', holder, revocation, LATER_NOW).output;
signCase('a link with the largest GitHub user id', holder, maxLink, NOW);
signCase('a link for another account', other, link, NOW, 'mismatch');
signCase('a link for another network', holder, otherNetwork, NOW, 'network');
signCase('a link issued too far ahead', holder, link, ISSUED * 1000 - 31000, 'future');
signCase('text that is not a link', holder, 'Sign this for me', NOW, 'format');

// link.verify
const verifyCase = (name, json, reason, { expected = {}, now = NOW } = {}) => {
    const result = record('link.verify', name, { record: json, expected, now }, () => verify(json, expected, now));
    if (reason) {
        expectRefusal(result, reason, name);
    } else {
        expectOutput(result, name);
    }
    return result;
};
const change = (base, changes) => recordJson({ ...base, ...changes });
verifyCase('a signed link', signedLink.json);
verifyCase('a signed link, everything expected', signedLink.json, null, { expected: { kind: 'link', githubId: ID, publicKey: holder.publicKey, address: holder.address } });
verifyCase('a signed revocation', signedRevocation.json, null, { now: LATER_NOW });
const otherAux = signatureOf(link, holder.keys, sha256('link vectors: another aux'));
verifyCase('a signature with another aux', change(signedLink.record, { signature: otherAux }));
verifyCase('the message altered after signing', change(signedLink.record, { message: withLine(link, 3, 'GitHub user id: 9999999002') }), 'signature');
verifyCase('the issue time altered after signing', change(signedLink.record, { message: withLine(link, 6, 'Issued at: 2026-09-26T12:34:57Z') }), 'signature');
verifyCase('a revocation with a link\'s signature', change(signedLink.record, { message: revocation }), 'signature', { now: LATER_NOW });
verifyCase('signed by another key, which the record names', change(signedLink.record, { publicKey: other.publicKey, signature: signatureOf(link, other.keys) }), 'record');
verifyCase('a message naming another key, signed by it', change(signedLink.record, {
    message: withLine(link, 5, `Public key: ${other.publicKey}`),
    publicKey: other.publicKey,
    signature: signatureOf(withLine(link, 5, `Public key: ${other.publicKey}`), other.keys),
}), 'address');
verifyCase('the record names another network', change(signedLink.record, { network: 'heartwood-devnet-v91' }), 'record');
verifyCase('the record names another algorithm', change(signedLink.record, { algorithm: 'ml-dsa-65' }), 'record');
verifyCase('the signature in capitals', change(signedLink.record, { signature: signedLink.record.signature.toUpperCase() }), 'signature');
verifyCase('a truncated signature', change(signedLink.record, { signature: signedLink.record.signature.slice(0, 126) }), 'signature');
const crlf = link.replace(/\n/g, '\r\n');
verifyCase('CRLF text with its own signature', change(signedLink.record, { message: crlf, signature: signatureOf(crlf, holder.keys) }), 'format');
const short = '0123456789abcdef0123456789abcdef';
verifyCase('a 32-byte message with its own signature', change(signedLink.record, { message: short, signature: signatureOf(short, holder.keys) }), 'format');
const lookalike = link.replace('IceRoot', 'IcеRoot');
verifyCase('non-ASCII text with its own signature', change(signedLink.record, { message: lookalike, signature: signatureOf(lookalike, holder.keys) }), 'format');
verifyCase('a member added', JSON.stringify({ ...JSON.parse(signedLink.json), comment: 'x' }), 'json');
verifyCase('a member missing', JSON.stringify({ ...JSON.parse(signedLink.json), network: undefined }), 'json');
verifyCase('a member that is not text', JSON.stringify({ ...JSON.parse(signedLink.json), network: 90 }), 'json');
verifyCase('not JSON', signedLink.json.slice(0, -1), 'json');
verifyCase('a JSON array', JSON.stringify([signedLink.json]), 'json');
verifyCase('the members in another order', JSON.stringify({
    network: NETWORK, algorithm: ALGORITHM, signature: signedLink.record.signature, publicKey: holder.publicKey, message: link,
}));

// link.history: the no-replay rule.
const historyCase = (name, message, recorded, now, reason) => {
    const result = record('link.history', name, { message, recorded, now }, () => history(message, recorded, now));
    if (reason) {
        expectRefusal(result, reason, name);
    } else {
        expectOutput(result, name);
    }
};
const entry = (event, at, changes = {}) => ({ network: NETWORK, githubId: ID, account: holder.address, event, at, ...changes });
const relink = build({ kind: 'link', githubId: ID, publicKey: holder.publicKey, issuedAt: LATER + 3600 });
const RELINK_NOW = (LATER + 3600) * 1000;
historyCase('a first link', link, [], NOW);
historyCase('a link later than the last link', relink, [entry('link', ISSUED * 1000)], RELINK_NOW);
historyCase('a link later than the last revocation', relink, [entry('link', ISSUED * 1000), entry('revocation', LATER * 1000)], RELINK_NOW);
historyCase('a link older than the last revocation', link, [entry('link', ISSUED * 1000 - 60000), entry('revocation', LATER * 1000)], LATER_NOW, 'replay');
historyCase('the same link posted again', link, [entry('link', ISSUED * 1000)], NOW, 'replay');
historyCase('a link older than a GitHub-side unlink', link, [entry('github-unlink', ISSUED * 1000 + 1000)], NOW, 'replay');
historyCase('a revocation of a recorded link', revocation, [entry('link', ISSUED * 1000)], LATER_NOW);
historyCase('a revocation naming a link that does not exist', revocation, [entry('link', ISSUED * 1000 - 1000)], LATER_NOW, 'unknown-link');
historyCase('a revocation with no history', revocation, [], LATER_NOW, 'unknown-link');
historyCase('a revocation older than a later link', revocation, [entry('link', ISSUED * 1000), entry('link', LATER * 1000 + 60000)], LATER_NOW, 'replay');
historyCase('a revocation posted again', revocation, [entry('link', ISSUED * 1000), entry('revocation', LATER * 1000)], LATER_NOW, 'replay');
historyCase('a revocation naming a link of another account', revocation, [entry('link', ISSUED * 1000, { account: other.address })], LATER_NOW, 'unknown-link');
historyCase('later entries of other ids, accounts and networks do not count', link, [
    entry('revocation', LATER * 1000, { githubId: ID + 1 }),
    entry('revocation', LATER * 1000, { account: other.address }),
    entry('revocation', LATER * 1000, { network: 'heartwood-devnet-v91' }),
], NOW);

// message.sign: plain signing refuses link and revocation text, and only that.
const plainCase = (name, message, reason) => {
    const result = record('message.sign', name, { passphrase: holder.passphrase, message, aux: hex(AUX) }, () => plainSign(holder, message));
    if (reason) {
        check(result.error && result.error.details.reason === reason, name);
    } else {
        expectOutput(result, name);
    }
};
plainCase('a link', link, LINK_TEXT);
plainCase('a revocation', revocation, LINK_TEXT);
plainCase('the first line alone', TITLE, LINK_TEXT);
plainCase('the revocation\'s first line alone', REVOCATION_TITLE, LINK_TEXT);
plainCase('a link that no reader accepts', `${link}\n`, LINK_TEXT);
plainCase('a link with a space before it', ` ${link}`);
plainCase('a link with CRLF line endings', link.replace(/\n/g, '\r\n'));
plainCase('the first line quoted', `Quoted: ${TITLE}`);

// ------------------------------------------------------------------------------------------------

const commit = execFileSync('git', ['-C', referenceDir, 'rev-parse', 'HEAD']).toString().trim();
const meta = {
    op: 'meta',
    format: 'heartwood-vectors/1',
    class: CLASS,
    records: records.length,
    generator: 'tools/oracle/gen-link-vectors.js',
    reference: { commit },
    node: process.version,
    network: { name: NETWORK, pubKeyHash: NETWORK_BYTE },
    algorithm: ALGORITHM,
    aux: hex(AUX),
};
fs.mkdirSync(outDir, { recursive: true });
const text = [meta, ...records].map((r) => JSON.stringify(r)).join('\n') + '\n';
fs.writeFileSync(path.join(outDir, `${CLASS}.jsonl`), text);
console.log(`${CLASS}: ${records.length} records`);

// MANIFEST.sha256, in the format of sha256sum, over every vector file of the directory.
const manifest = fs
    .readdirSync(outDir)
    .filter((file) => file.endsWith('.jsonl'))
    .sort()
    .map((file) => `${hex(sha256(fs.readFileSync(path.join(outDir, file))))}  ${file}`);
fs.writeFileSync(path.join(outDir, 'MANIFEST.sha256'), manifest.join('\n') + '\n');
