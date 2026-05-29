'use strict';

const net = require('net');
const { dumps, loads } = require('./pickle');

const END   = Buffer.from('<F2B_END_COMMAND>');
const CLOSE = Buffer.from('<F2B_CLOSE_COMMAND>');

/**
 * Send a command to fail2ban and return the response.
 * @param {string} socketPath
 * @param {string[]} cmd
 * @returns {Promise<*>}
 */
function send(socketPath, cmd) {
    return new Promise((resolve, reject) => {
        const conn = net.createConnection(socketPath);
        let chunks = [];

        conn.once('error', reject);

        conn.once('connect', () => {
            conn.write(Buffer.concat([dumps(cmd), END]));
        });

        conn.on('data', (chunk) => {
            chunks.push(chunk);
            const data = Buffer.concat(chunks);
            // Stop reading once END marker appears in the last 32 bytes
            if (data.length >= END.length && data.subarray(-32).includes(END)) {
                conn.write(Buffer.concat([CLOSE, END]));
                conn.destroy();

                // Strip trailing END marker
                let payload = data;
                const tail = data.subarray(data.length - END.length);
                if (tail.equals(END)) payload = data.subarray(0, data.length - END.length);

                try {
                    const result = loads(payload);
                    // result = [status_code, response]
                    // status_code: 0 = success, non-zero = error
                    if (result[0] !== 0) {
                        reject(new Error(`fail2ban: ${result[1]}`));
                    } else {
                        resolve(result[1]);
                    }
                } catch (err) {
                    reject(err);
                }
            }
        });
    });
}

module.exports = { send };
