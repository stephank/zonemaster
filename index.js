#!/usr/bin/env node
'use strict';

// FIXME: Slaves parameter whitelist

// FIXME: Send NOTIFY.

// FIXME: Async soaFn.

// FIXME: Intelligent batching. Right now, we send a fairly safe 20 records per
// packet, but we should probably fill up to a certain amount of bytes.

const net = require('net');
const stream = require('stream');
const frame = require('frame-stream');
const Packet = require('native-dns-packet');

const RCODE = Packet.consts.NAME_TO_RCODE;
const QCLASS = Packet.consts.NAME_TO_QCLASS;
const QTYPE = Packet.consts.NAME_TO_QTYPE;
const OPCODE = Packet.consts.NAME_TO_OPCODE;

// Main export, returns a TCP server.
exports = module.exports = (params) => {
    // Handle user errors.
    params = Object.create(params);
    params.errorFn = (conn, req, err) => {
        err.req = req;
        conn.emit('error', err);
    };

    // Create the server and handle connections.
    const server = net.createServer((conn) => {
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
        conn.readableWrap = exports.wrapReadable(conn);
        conn.writableWrap = exports.wrapWritable(conn, params.packetSize || 4096);

        // Handle messages.
        exports.processStream(conn, conn.readableWrap, conn.writableWrap, params);
    });

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
// The context parameter is passed to callback functions.
exports.processStream = (context, readable, writable, params) => {
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

        // Send to first packet with the SOA record, which
        // is the same for all questions we support.
        const soa = params.soaFn(context, req);
        pkt.header.aa = 1;
        pkt.answer = [soa];
        writable.write(pkt);

        // Stop here if it's just a SOA query.
        if (q.type !== QTYPE.AXFR && q.type !== QTYPE.IXFR)
            return;

        // Records pending to be sent in a batch.
        let pending = [];

        // Call the body builder function.
        params.bodyFn(
            context, req, soa,
            // Record emit function.
            (record) => {
                pending.push(record);

                // Send a packet if we've reached the batch limit.
                if (pending.length >= (params.batchSize || 20)) {
                    const pkt = new ResponsePacket(req);
                    pkt.header.aa = 1;
                    pkt.answer = pending;
                    writable.write(pkt);

                    pending = [];
                }
            },
            // Final callback function.
            (err) => {
                if (err) {
                    // Send a server failure packet.
                    const pkt = new ResponsePacket(req);
                    pkt.header.aa = 1;
                    pkt.header.rcode = RCODE.SERVFAIL;
                    writable.write(pkt);

                    // Call the error callback.
                    if (params.errorFn)
                        params.errorFn(context, req, err);
                }
                else {
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
            }
        );
    });
};

// Wrap a readable or writable stream with
// transforms to read or write DNS messages.
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

// Transform between DNS messages and DNS message buffers.
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

// Transform between DNS message buffers and a plain data stream.
const frameOptions = { lengthSize: 2 };
exports.createTcpFrameDecoder = () => frame.decode(frameOptions);
exports.createTcpFrameEncoder = () => frame.encode(frameOptions);
