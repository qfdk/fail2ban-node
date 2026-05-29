'use strict';

const { send } = require('./lib/socket');

const DEFAULT_SOCKET = '/var/run/fail2ban/fail2ban.sock';

class Fail2BanClient {
    /**
     * @param {string} [socketPath]
     */
    constructor(socketPath = DEFAULT_SOCKET) {
        this.socket = socketPath;
    }

    _send(...args) {
        return send(this.socket, args);
    }

    /** @returns {Promise<boolean>} */
    async ping() {
        try {
            const res = await this._send('ping');
            return res === 'pong';
        } catch {
            return false;
        }
    }

    /**
     * Get global status.
     * @returns {Promise<{ total: number, list: string[] }>}
     */
    async status() {
        const res = await this._send('status');
        // res = [('Number of jail', n), ('Jail list', 'a, b')]
        const total = res[0][1];
        const raw   = res[1][1];
        const list  = raw ? raw.split(',').map(s => s.trim()).filter(Boolean) : [];
        return { total, list };
    }

    /**
     * Get detailed status for a specific jail.
     * @param {string} jail
     * @returns {Promise<{
     *   currentlyFailed: number,
     *   totalFailed: number,
     *   fileList: string[],
     *   currentlyBanned: number,
     *   totalBanned: number,
     *   bannedIPs: string[]
     * }>}
     */
    async jailStatus(jail) {
        const res = await this._send('status', jail);
        // res = [('Filter', [...]), ('Actions', [...])]
        const filter  = Object.fromEntries(res[0][1].map(([k, v]) => [k, v]));
        const actions = Object.fromEntries(res[1][1].map(([k, v]) => [k, v]));
        return {
            currentlyFailed: filter['Currently failed'] ?? 0,
            totalFailed:     filter['Total failed']     ?? 0,
            fileList:        filter['File list']        ?? [],
            currentlyBanned: actions['Currently banned'] ?? 0,
            totalBanned:     actions['Total banned']     ?? 0,
            bannedIPs:       actions['Banned IP list']  ?? [],
        };
    }

    /**
     * Ban an IP in a jail.
     * @param {string} jail
     * @param {string} ip
     */
    ban(jail, ip) {
        return this._send('set', jail, 'banip', ip);
    }

    /**
     * Unban an IP from a jail.
     * @param {string} jail
     * @param {string} ip
     */
    unban(jail, ip) {
        return this._send('set', jail, 'unbanip', ip);
    }

    /** Reload fail2ban configuration. */
    reload() {
        return this._send('reload');
    }

    /** Unban all IPs across all jails. */
    unbanAll() {
        return this._send('unban', '--all');
    }
}

module.exports = Fail2BanClient;
