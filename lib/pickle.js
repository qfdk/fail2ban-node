'use strict';

// Pickle protocol 5 opcodes used by fail2ban
const OP = {
    PROTO:            0x80,
    FRAME:            0x95,
    STOP:             0x2e,
    MARK:             0x28,
    NONE:             0x4e,
    NEWTRUE:          0x88,
    NEWFALSE:         0x89,
    BININT1:          0x4b,
    BININT2:          0x4d,
    BININT:           0x4a,
    LONG1:            0x8a,
    BINFLOAT:         0x47,
    SHORT_BINUNICODE: 0x8c,
    BINUNICODE:       0x58,
    SHORT_BINBYTES:   0x43,
    BINBYTES:         0x42,
    BYTEARRAY8:       0x96,
    EMPTY_LIST:       0x5d,
    EMPTY_TUPLE:      0x29,
    EMPTY_DICT:       0x7d,
    TUPLE1:           0x85,
    TUPLE2:           0x86,
    TUPLE3:           0x87,
    TUPLE:            0x74,
    LIST:             0x6c,
    APPEND:           0x61,
    APPENDS:          0x65,
    SETITEM:          0x73,
    SETITEMS:         0x75,
    MEMOIZE:          0x94,
    BINPUT:           0x71,
    LONG_BINPUT:      0x72,
    BINGET:           0x68,
    LONG_BINGET:      0x6a,
    // Protocol 4+ object construction
    STACK_GLOBAL:     0x93,
    REDUCE:           0x52,
    BUILD:            0x62,
    NEWOBJ:           0x81,
    NEWOBJ_EX:        0x92,
};

// Safe builtins we recognise when reconstructing Python objects.
// fail2ban wraps IPs as builtins.str(ip_string).
const SAFE_BUILTINS = {
    'builtins.str':   (args) => String(args[0]),
    'builtins.int':   (args) => parseInt(args[0], 10),
    'builtins.float': (args) => parseFloat(args[0]),
    'builtins.bool':  (args) => Boolean(args[0]),
};

const MARK = Symbol('MARK');

/**
 * Deserialize a Python pickle buffer into a JavaScript value.
 * Handles protocols 2–5 and the types fail2ban uses in responses.
 * @param {Buffer} buf
 * @returns {*}
 */
function loads(buf) {
    const stack = [];
    const memo = new Map();
    let pos = 0;

    const read = (n) => { const s = buf.slice(pos, pos + n); pos += n; return s; };
    const byte = () => buf[pos++];

    while (pos < buf.length) {
        const op = byte();
        switch (op) {
            case OP.PROTO:      byte(); break;
            case OP.FRAME:      read(8); break;
            case OP.NONE:       stack.push(null); break;
            case OP.NEWTRUE:    stack.push(true); break;
            case OP.NEWFALSE:   stack.push(false); break;

            case OP.BININT1:    stack.push(byte()); break;
            case OP.BININT2: {
                const lo = byte(), hi = byte();
                stack.push(lo | (hi << 8));
                break;
            }
            case OP.BININT:     stack.push(read(4).readInt32LE(0)); break;
            case OP.LONG1: {
                const n = byte();
                let val = 0;
                for (let i = 0; i < n; i++) val |= byte() << (8 * i);
                stack.push(val);
                break;
            }

            case OP.SHORT_BINUNICODE: stack.push(read(byte()).toString('utf8')); break;
            case OP.BINUNICODE:       stack.push(read(read(4).readUInt32LE(0)).toString('utf8')); break;
            case OP.SHORT_BINBYTES:   stack.push(read(byte())); break;
            case OP.BINBYTES:         stack.push(read(read(4).readUInt32LE(0))); break;
            case OP.BYTEARRAY8: {
                const len = Number(read(8).readBigUInt64LE(0));
                stack.push(read(len));
                break;
            }

            case OP.MARK:        stack.push(MARK); break;
            case OP.EMPTY_LIST:  stack.push([]); break;
            case OP.EMPTY_TUPLE: stack.push([]); break;
            case OP.EMPTY_DICT:  stack.push({}); break;

            case OP.TUPLE1: { const a = stack.pop(); stack.push([a]); break; }
            case OP.TUPLE2: { const b = stack.pop(), a = stack.pop(); stack.push([a, b]); break; }
            case OP.TUPLE3: { const c = stack.pop(), b = stack.pop(), a = stack.pop(); stack.push([a, b, c]); break; }
            case OP.TUPLE:
            case OP.LIST: {
                const items = [];
                while (stack[stack.length - 1] !== MARK) items.unshift(stack.pop());
                stack.pop();
                stack.push(items);
                break;
            }

            case OP.APPEND:  { const v = stack.pop(); stack[stack.length - 1].push(v); break; }
            case OP.APPENDS: {
                const items = [];
                while (stack[stack.length - 1] !== MARK) items.unshift(stack.pop());
                stack.pop();
                stack[stack.length - 1].push(...items);
                break;
            }
            case OP.SETITEM: {
                const v = stack.pop(), k = stack.pop();
                stack[stack.length - 1][k] = v;
                break;
            }
            case OP.SETITEMS: {
                const pairs = [];
                while (stack[stack.length - 1] !== MARK) pairs.unshift(stack.pop());
                stack.pop();
                const dict = stack[stack.length - 1];
                for (let i = 0; i < pairs.length; i += 2) dict[pairs[i]] = pairs[i + 1];
                break;
            }

            case OP.MEMOIZE:     { memo.set(memo.size, stack[stack.length - 1]); break; }
            case OP.BINPUT:      { memo.set(byte(), stack[stack.length - 1]); break; }
            case OP.LONG_BINPUT: { memo.set(read(4).readUInt32LE(0), stack[stack.length - 1]); break; }
            case OP.BINGET:      { stack.push(memo.get(byte())); break; }
            case OP.LONG_BINGET: { stack.push(memo.get(read(4).readUInt32LE(0))); break; }

            case OP.BINFLOAT: {
                stack.push(read(8).readDoubleBE(0));
                break;
            }

            // Object construction: used by fail2ban to wrap IPAddr as builtins.str(ip)
            case OP.STACK_GLOBAL: {
                const name = stack.pop(), module = stack.pop();
                const key = `${module}.${name}`;
                const fn = SAFE_BUILTINS[key] ?? ((...args) => { throw new Error(`Unsupported global: ${key}`); });
                stack.push(fn);
                break;
            }
            case OP.REDUCE: {
                const args = stack.pop(), fn = stack.pop();
                stack.push(typeof fn === 'function' ? fn(args) : fn);
                break;
            }
            case OP.BUILD: {
                // state dict applied to instance — skip for our use case
                stack.pop();
                break;
            }
            case OP.NEWOBJ:
            case OP.NEWOBJ_EX: {
                const args = stack.pop(), cls = stack.pop();
                stack.push(typeof cls === 'function' ? cls(Array.isArray(args) ? args : [args]) : cls);
                break;
            }

            case OP.STOP: return stack[stack.length - 1];

            default: throw new Error(`Unknown pickle opcode 0x${op.toString(16)} at pos ${pos - 1}`);
        }
    }
    return stack[stack.length - 1];
}

/**
 * Serialize a list of strings into a Python pickle (protocol 5) buffer.
 * fail2ban commands are always string arrays, e.g. ['status', 'sshd'].
 * @param {string[]} arr
 * @returns {Buffer}
 */
function dumps(arr) {
    const parts = [Buffer.from([OP.EMPTY_LIST, OP.MEMOIZE])];

    if (arr.length === 1) {
        const s = Buffer.from(arr[0], 'utf8');
        parts.push(Buffer.from([OP.SHORT_BINUNICODE, s.length]));
        parts.push(s);
        parts.push(Buffer.from([OP.MEMOIZE, OP.APPEND]));
    } else {
        parts.push(Buffer.from([OP.MARK]));
        for (const str of arr) {
            const s = Buffer.from(str, 'utf8');
            parts.push(Buffer.from([OP.SHORT_BINUNICODE, s.length]));
            parts.push(s);
            parts.push(Buffer.from([OP.MEMOIZE]));
        }
        parts.push(Buffer.from([OP.APPENDS]));
    }
    parts.push(Buffer.from([OP.STOP]));

    const payload = Buffer.concat(parts);
    const lenBuf = Buffer.alloc(8);
    lenBuf.writeBigUInt64LE(BigInt(payload.length));
    return Buffer.concat([Buffer.from([OP.PROTO, 5, OP.FRAME]), lenBuf, payload]);
}

module.exports = { dumps, loads };
