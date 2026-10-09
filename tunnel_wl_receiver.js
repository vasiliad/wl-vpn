'use strict';
// tunnel_wl_receiver.js — Haraka plugin for wl-vpn
// Receives SMTP messages from wl-client containing:
//   base64(zstd(framed_ip_packets))  — regular tunnel data
//   base64(zstd(\x00WL-REG\x00 + json))  — registration packet
// Forwards raw decompressed bytes to wl-server.py via Unix socket /tmp/wl_tun.sock

const net  = require('net');
const { Writable } = require('stream');
const zstd = require('@mongodb-js/zstd');

const SOCK_PATH = '/tmp/wl_tun.sock';

let sockClient = null;
let reconnecting = false;

function getSocket(logfn) {
    if (sockClient && !sockClient.destroyed) return sockClient;
    if (reconnecting) return null;
    reconnecting = true;
    const c = net.createConnection(SOCK_PATH);
    c.on('connect', () => {
        sockClient = c;
        reconnecting = false;
        if (logfn) logfn('[wl] unix socket connected');
    });
    c.on('error', (err) => {
        if (logfn) logfn('[wl] unix socket error: ' + err.message);
        sockClient = null;
        reconnecting = false;
    });
    c.on('close', () => {
        sockClient = null;
        reconnecting = false;
    });
    return null;  // not ready yet, will be ready on next message
}

exports.register = function () {
    this.register_hook('rcpt',      'accept_all_rcpt');
    this.register_hook('data_post', 'process_payload');

    // Pre-warm socket connection
    getSocket(this.loginfo.bind(this));
    this.loginfo('[wl] tunnel_wl_receiver loaded, sock=' + SOCK_PATH);
};

exports.accept_all_rcpt = function (next) {
    return next(OK);
};

exports.process_payload = function (next, connection) {
    const chunks = [];

    const sink = new Writable({
        write(chunk, _enc, cb) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            cb();
        }
    });

    sink.on('finish', async () => {
        try {
            let payload = Buffer.concat(chunks);
            if (!payload.length) return next(OK);

            // Strip MIME headers (separated by \r\n\r\n)
            const sep = payload.indexOf('\r\n\r\n');
            if (sep !== -1) payload = payload.subarray(sep + 4);
            if (!payload.length) return next(OK);

            // base64 decode → zstd decompress
            const compressed   = Buffer.from(payload.toString('ascii').trim(), 'base64');
            const decompressed = await zstd.decompress(compressed);

            connection.logdebug('[wl] payload: ' + decompressed.length + ' bytes decompressed');

            // Write raw decompressed data to unix socket (already framed by wl-client)
            const frame = decompressed;  // data is already [4-byte len][payload]...

            // Try persistent socket first, fallback to one-shot with retry
            const sock = getSocket(connection.loginfo.bind(connection));
            if (sock && !sock.destroyed) {
                sock.write(frame);
            } else {
                // Retry one-shot connection up to 3 times with 200ms backoff
                let attempts = 0;
                const tryConnect = () => {
                    attempts++;
                    const c = net.createConnection(SOCK_PATH, () => {
                        c.write(frame);
                        c.end();
                    });
                    c.on('error', (err) => {
                        if (attempts < 3) {
                            setTimeout(tryConnect, 200 * attempts);
                        } else {
                            connection.logerror('[wl] sock failed after ' + attempts + ' attempts: ' + err.message);
                        }
                    });
                };
                tryConnect();
            }

        } catch (err) {
            connection.logerror('[wl] process_payload error: ' + err.message);
        }
        return next(OK);
    });

    sink.on('error', (err) => {
        connection.logerror('[wl] sink error: ' + err.message);
        return next(OK);
    });

    connection.transaction.message_stream.pipe(sink, {
        dot_stuffing: false,
        ending_dot:   false,
        end:          true,
    });
};
