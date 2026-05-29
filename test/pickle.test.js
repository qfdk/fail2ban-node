'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { dumps, loads } = require('../lib/pickle');

// Real bytes captured from fail2ban server (Python 3.11, protocol 5)
const REAL_STATUS_RESPONSE = Buffer.from(
    '80059533000000000000004b005d94288c0e4e756d626572206f66206a61696c944b0186948c094a61696c206c697374948c04737368649486946586942e',
    'hex'
);

test('loads: parses real fail2ban status response', () => {
    const result = loads(REAL_STATUS_RESPONSE);
    assert.deepEqual(result, [0, [['Number of jail', 1], ['Jail list', 'sshd']]]);
});

test('loads: parses integers', () => {
    // PROTO 5, FRAME, BININT1(42), STOP
    const buf = Buffer.from('80059504000000000000004b2a2e', 'hex');
    assert.equal(loads(buf), 42);
});

test('loads: parses None', () => {
    const buf = Buffer.from('8005950100000000000000' + '4e2e', 'hex');
    assert.equal(loads(buf), null);
});

test('loads: parses boolean true/false', () => {
    const bufT = Buffer.from('8005950100000000000000' + '882e', 'hex');
    const bufF = Buffer.from('8005950100000000000000' + '892e', 'hex');
    assert.equal(loads(bufT), true);
    assert.equal(loads(bufF), false);
});

test('dumps: produces valid pickle for single-item list', () => {
    const encoded = dumps(['status']);
    // Real bytes from Python: 8005950d000000000000005d948c0673746174757394612e
    assert.equal(encoded.toString('hex'), '8005950d000000000000005d948c0673746174757394612e');
});

test('dumps: produces valid pickle for two-item list', () => {
    const encoded = dumps(['status', 'sshd']);
    // Decode it back and verify
    const decoded = loads(encoded);
    assert.deepEqual(decoded, ['status', 'sshd']);
});

test('dumps/loads roundtrip for multi-arg commands', () => {
    const cmds = [
        ['ping'],
        ['status'],
        ['status', 'sshd'],
        ['set', 'sshd', 'banip', '1.2.3.4'],
        ['set', 'sshd', 'unbanip', '1.2.3.4'],
        ['reload'],
    ];
    for (const cmd of cmds) {
        assert.deepEqual(loads(dumps(cmd)), cmd, `roundtrip failed for ${JSON.stringify(cmd)}`);
    }
});
