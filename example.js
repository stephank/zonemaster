#!/usr/bin/env node
'use strict';
/*eslint no-unused-vars:0, no-console:0 */

// An example zonemaster server. Run this, then query it using e.g.:
//   dig -t AXFR -p 10053 @localhost test.lan

const zonemaster = require('.');

const QCLASS = zonemaster.consts.NAME_TO_QCLASS;
const QTYPE = zonemaster.consts.NAME_TO_QTYPE;

// Utility function used to format log messages.
const formatLog = (conn, req, message) => {
    const parts = [];
    if (conn && conn.remoteAddress)
        parts.push(conn.remoteAddress);
    if (req)
        parts.push(zonemaster.formatQuestion(req));
    if (message)
        parts.push(message);
    return parts.join(' - ');
};

// Build the zonemaster server.
// Callback functions are called with the parameters object as context.
const server = zonemaster({
    // The domain we serve.
    domain: 'test.lan',
    // Log requests the stdout.
    logFn(conn, req) {
        console.log(formatLog(conn, req));
    },
    // Build a dummy SOA-record. This particular record has some very short
    // refresh times, which is fun to test with.
    soaFn(conn, req, cb) {
        cb(null, {
            class: QCLASS.IN,
            type: QTYPE.SOA,
            name: this.domain,
            ttl: 3600,
            primary: 'ns.' + this.domain + '.',
            admin: 'info.' + this.domain + '.',
            serial: Math.floor(Date.now() / 1000),
            refresh: 10,
            retry: 10,
            expiration: 60,
            minimum: 3600
        });
    },
    // Build the body of the AXFR/IXFR-request, that is, everything but the
    // SOA-record. The SOA-record from soaFn is passed as a parameter merely
    // because it might be useful.
    //
    // To build the body, call emit with an object for every record to send.
    // Records are automatically batched in packets. Finally, call cb when
    // complete, optionally with an error.
    //
    // If IXFR is not supported, simply treat everything like an AXFR.
    // Otherwise, determine the type from `req.question[0].type` and the last
    // serial from `req.authority[0].serial` and act accordingly.
    bodyFn(conn, req, soa, emit, cb) {
        // Fake an NS-record, and its glue AAAA-record.
        emit({
            class: QCLASS.IN,
            type: QTYPE.NS,
            name: this.domain,
            ttl: 3600,
            data: 'ns.' + this.domain + '.'
        });
        emit({
            class: QCLASS.IN,
            type: QTYPE.AAAA,
            name: 'ns.' + this.domain,
            ttl: 3600,
            address: '::1'
        });
        // Artificial delay.
        setTimeout(() => {
            // Fake a whole bunch of AAAA-records.
            for (let i = 1; i < 255; i++) {
                emit({
                    class: QCLASS.IN,
                    type: QTYPE.AAAA,
                    name: i + '.' + this.domain,
                    ttl: 3600,
                    address: '::1'
                });
            }
            // Finalize.
            cb(null);
        }, 1000);
    }
});

// Log errors to stderr.
server.on('error', (err) => {
    console.error(formatLog(err.connection, err.request, err.stack));
});

// Configure some slaves.
server.setSlaves(['localhost@11053'], (err) => {
    if (err) {
        console.error(err.stack);
        process.exit(1);
    }

    // Start listening.
    server.listen(10053, () => {
        console.log('Listening on port ' + server.address().port);

        // Immediately send a NOTIFY to slaves.
        server.notify();
    });
});
