#!/usr/bin/env node
'use strict';

const net = require('net');
const dns = require('dns');
const stream = require('stream');
const frame = require('frame-stream');
const Packet = require('native-dns-packet');

const RCODE = Packet.consts.NAME_TO_RCODE;
const QCLASS = Packet.consts.NAME_TO_QCLASS;
const QTYPE = Packet.consts.NAME_TO_QTYPE;
const OPCODE = Packet.consts.NAME_TO_OPCODE;

const QCLASS_NAMES = Packet.consts.QCLASS_TO_NAME;
const QTYPE_NAMES = Packet.consts.QTYPE_TO_NAME;
const OPCODE_NAMES = Packet.consts.OPCODE_TO_NAME;

// Main export, returns a TCP server.
//
// Required properties of params are:
//
//  - `domain`: The domain name to serve.
//
//  - `slaves`: Array of slave hosts to whitelist and notify.
//    See `setSlaves` for a description.
//
//  - `soaFn`: Callback to build the SOA-record.
//    Signature is `(connection, request) => soaRecord`
//
//  - `bodyFn`: Callback to build the AXFR/IXFR-question response.
//    Signature is `(connection, request, soaRecord, emitFn, callback)`
//    `emitFn` signature is `(record)`
//    `callback` signature is `(error)`
//
// Optional properties of params are:
//
//  - `logFn`: Function called for every request to write an access log entry.
//    Signature is `(connection, request)`
//
//  - `packetSize`: Maximum packet size to use for sending. (default: 4096)
//
//  - `batchSize`: Maximum records to send in one packet. (default: 20)
//
// The parameters can be changed at runtime by simply setting new values on the
// same params object. (Also available as `server.params`.)
//
// The exception is `slaves`, which acts like a call to `setSlaves`.
exports = module.exports = (params) => {
    // Create the server and handle connections.
    const server = net.createServer((conn) => {
        const addr = exports.sanitizeAddress(conn.remoteAddress);

        // Check against the list of configured slaves.
        const slave = conn.slave = server.slavesByIp[addr];
        if (!slave)
            return conn.destroy();

        // Handle connection errors.
        conn.on('error', (err) => {
            // Typical NSD behavior is to not query SOA, but just issue AXFR /
            // IXFR and check the first packet, then close the connection if
            // the serial hasn't changed.
            if (err.code === 'EPIPE')
                return;

            err.connection = conn;
            server.emit('error', err);
        });

        // Wrap the duplex stream.
        exports.addWrappers(conn, params.packetSize || 4096);

        // Handle messages.
        exports.processStream(
            conn, conn.readableWrap, conn.writableWrap, params,
            // Handle user errors.
            (conn, req, err) => {
                err.request = req;
                conn.emit('error', err);
            }
        );
    });

    // The currently configured slave list.
    server.slaves = [];
    // Slaves indexed by IP.
    server.slavesByIp = Object.create(null);
    // The parameters object.
    server.params = params;

    // Notify configured slaves that the zone has changed.
    server.notify = () => {
        // Build the request packet.
        const req = new Packet();
        req.header.opcode = OPCODE.NOTIFY;
        req.header.aa = 1;
        req.question = [{
            class: QCLASS.IN,
            type: QTYPE.SOA,
            name: params.domain
        }];

        // Connect to every slave.
        server.slaves.forEach((slave) => {
            const conn = net.connect(slave.port, slave.host);
            conn.slave = slave;

            // Wrap the duplex stream.
            exports.addWrappers(conn, params.packetSize || 4096);

            // Send in fire and forget fashion.
            // FIXME: Wait for response, or retry.
            conn.on('connect', () => {
                conn.writableWrap.end(req);
            });

            // Handle connection errors.
            conn.on('error', (err) => {
                err.request = req;
                err.connection = conn;
                server.emit('error', err);
            });
        });
    };

    // Set the slave servers to whitelist and notify. This function also
    // resolves hosts, and whitelists all addresses. (But only one is
    // notified.)
    //
    // Takes an array which may contain:
    //  - strings with an host/ip,
    //  - strings with host/ip and port in NSD notation (`host@port`), or
    //  - an object with `host`, and `port` properties.
    //
    // A callback can be specified to capture errors. If not specified, errors
    // are emitted on the server object.
    //
    // (In the future, objects may contain more settings, such as keys.)
    server.setSlaves = (slaves, cb) => {
        // Expand strings to objects.
        slaves = slaves.map((slave) => {
            if (typeof(slave) === 'string') {
                const parts = slave.split('@', 2);
                return {
                    host: parts[0],
                    port: parseInt(parts[1], 10) || 53
                };
            }
            else {
                return Object.assign({}, slave);
            }
        });

        // Resolve hosts.
        var pending = slaves.length;
        if (pending === 0)
            onComplete();
        slaves.forEach((slave) => {
            dns.lookup(slave.host, { all: true }, (err, addrs) => {
                // Aborted.
                if (pending === -1)
                    return;

                // Handle errors.
                if (err) {
                    pending = -1;
                    return cb ? cb(err) : server.emit('error', err);
                }

                // Process result.
                pending -= 1;
                slave.addresses = addrs.map(
                    (addr) => exports.sanitizeAddress(addr.address)
                );

                // Check if we're done.
                if (pending === 0)
                    onComplete();
            });
        });

        // Finalize.
        function onComplete() {
            // Build the IP index.
            const slavesByIp = Object.create(null);
            slaves.forEach((slave) => {
                slave.addresses.forEach((addr) => {
                    slavesByIp[addr] = slave;
                });
            });

            // Commit.
            server.slaves = slaves;
            server.slavesByIp = slavesByIp;

            // Callback.
            if (cb)
                cb();
        }
    };

    // Set the slave list from parameters.
    if (params.slaves)
        server.setSlaves(params.slaves);

    return server;
};

// Simple packet helper for our responses.
class ResponsePacket extends Packet {
    constructor(req) {
        super();
        this.header.id = req.header.id;
        this.header.qr = 1;
    }
}

// Handle messages on the read/write packet stream pair.
//
// The `context` parameter is passed to callback functions.
// See the main export for a description of the params object.
//
// `errorFn` is optional and called on user callback errors.
exports.processStream = (context, readable, writable, params, errorFn) => {
    // Packet listener.
    readable.on('data', (req) => {
        // Create the first response packet.
        const pkt = new ResponsePacket(req);
        pkt.question = req.question;

        // Accept exactly one question.
        if (req.question.length !== 1) {
            pkt.header.rcode = RCODE.FORMERR;
            return writable.write(pkt);
        }

        // Optional logging hook.
        const q = req.question[0];
        if (params.logFn)
            params.logFn(context, req);

        // Accept only SOA, AXFR and IXFR queries
        // for class IN and our exact domain.
        if (
            req.header.opcode !== OPCODE.QUERY ||
            q.class !== QCLASS.IN ||
            q.name !== params.domain || (
                q.type !== QTYPE.SOA &&
                q.type !== QTYPE.AXFR &&
                q.type !== QTYPE.IXFR
            )
        ) {
            pkt.header.rcode = RCODE.NOTIMP;
            return writable.write(pkt);
        }

        // Call the SOA-record builder function.
        params.soaFn(context, req, (err, soa) => {
            if (err)
                return fail(err, true);

            // Send to first packet with the SOA record, which
            // is the same for all questions we support.
            pkt.header.aa = 1;
            pkt.answer = [soa];
            writable.write(pkt);

            // Stop here if it's just a SOA query.
            if (q.type !== QTYPE.AXFR && q.type !== QTYPE.IXFR)
                return;

            // Records pending to be sent in a batch.
            let pending = [];

            // Call the body builder function.
            params.bodyFn(context, req, soa, emitFn, bodyCb);

            // Record emit function.
            function emitFn(record) {
                pending.push(record);

                // Send a packet if we've reached the batch limit.
                // FIXME: Intelligent batching. Right now, we send a fairly
                // safe 20 records per packet, but we should probably fill
                // up to a certain amount of bytes.
                if (pending.length >= (params.batchSize || 20)) {
                    const pkt = new ResponsePacket(req);
                    pkt.header.aa = 1;
                    pkt.answer = pending;
                    writable.write(pkt);

                    pending = [];
                }
            }

            // Final callback function.
            function bodyCb(err) {
                if (err)
                    return fail(err);

                // Flush any batched records.
                if (pending.length) {
                    const pkt = new ResponsePacket(req);
                    pkt.header.aa = 1;
                    pkt.answer = pending;
                    writable.write(pkt);
                }

                // Send closing packet, repeating the SOA record.
                const pkt = new ResponsePacket(req);
                pkt.header.aa = 1;
                pkt.answer = [soa];
                writable.write(pkt);
            }
        });

        // Handle user failure.
        function fail(err, isFirst) {
            // Send a server failure packet.
            const pkt = new ResponsePacket(req);
            pkt.header.aa = 1;
            pkt.header.rcode = RCODE.SERVFAIL;
            if (isFirst)
                pkt.question = req.question;
            writable.write(pkt);

            // Call the error callback.
            if (errorFn)
                errorFn(context, req, err);
        }
    });
};

// Wrap a readable or writable stream with transforms so that the wrapped
// versions operate on Packet instances.
//
// The writable function takes a maximum packet size, beyond which the DNS
// packet is truncated.
exports.wrapWritable = (wstream, packetSize) => {
    const start = exports.createWriter(packetSize);
    start
        .pipe(exports.createTcpFrameEncoder())
        .pipe(wstream);
    return start;
};
exports.wrapReadable = (rstream) => {
    return rstream
        .pipe(exports.createTcpFrameDecoder())
        .pipe(exports.createParser())
};

// How we commonly decorate a connection.
exports.addWrappers = (conn, packetSize) => {
    conn.readableWrap = exports.wrapReadable(conn);
    conn.writableWrap = exports.wrapWritable(conn, packetSize);
};

// Transforms that implement the DNS message format. These operate on message
// buffers on one end, and on Packet instances on the other end. (Both in
// object mode.)
//
// The writable function takes a maximum packet size, beyond which the DNS
// packet is truncated.
exports.createParser = () => new stream.Transform({
    readableObjectMode: true,
    writableObjectMode: true,
    transform: function(data, unused, cb) {
        try { data = Packet.parse(data); }
        catch (err) { return cb(err); }
        cb(null, data);
    }
});
exports.createWriter = (packetSize) => new stream.Transform({
    readableObjectMode: true,
    writableObjectMode: true,
    transform: function(packet, unused, cb) {
        const data = new Buffer(packetSize);
        let size;
        try { size = Packet.write(data, packet); }
        catch (err) { return cb(err); }
        cb(null, data.slice(0, size));
    }
});

// Transforms that implement DNS TCP framing. These operate on plain streams of
// data on one end, and message buffers (in object mode) on the other end.
const frameOptions = { lengthSize: 2 };
exports.createTcpFrameDecoder = () => frame.decode(frameOptions);
exports.createTcpFrameEncoder = () => frame.encode(frameOptions);

// Utility: Gets rid of IPv4 mapped addresses.
exports.sanitizeAddress = (addr) => {
    if (addr.slice(0, 7) === '::ffff:')
        return addr.slice(7);
    else
        return addr;
};

// Utility: Format essential parts of a request as a string for logging.
exports.formatQuestion = (req) => {
    const q = req.question[0];
    return OPCODE_NAMES[req.header.opcode] + ' ' +
           QCLASS_NAMES[q.class] + ' ' +
           QTYPE_NAMES[q.type];
};

// Utility: Re-export constants.
exports.consts = Packet.consts;
