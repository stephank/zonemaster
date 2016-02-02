#!/usr/bin/env node
'use strict';

const t = require('tap');
const fs = require('fs');
const net = require('net');
const path = require('path');
const zonemaster = require('.');
const concatStream = require('concat-stream');

const QCLASS = zonemaster.consts.NAME_TO_QCLASS;
const QTYPE = zonemaster.consts.NAME_TO_QTYPE;

const readFixture = (name) => {
    return fs.readFileSync(
        path.join(__dirname, 'fixtures', name + '.bin')
    );
};

const createMaster = (t) => {
    const master = zonemaster({
        domain: 'test.lan',
        batchSize: 2,
        logFn() {
            t.pass('logFn called');
        },
        soaFn(conn, req, cb) {
            t.pass('soaFn called');
            cb(null, {
                class: QCLASS.IN,
                type: QTYPE.SOA,
                name: 'test.lan',
                ttl: 3600,
                primary: 'ns.test.lan.',
                admin: 'admin.test.lan.',
                serial: 2014101601,
                refresh: 172800,
                retry: 900,
                expiration: 1209600,
                minimum: 3600
            });
        },
        bodyFn(conn, req, soa, emit, cb) {
            t.pass('bodyFn called');
            emit({
                class: QCLASS.IN,
                type: QTYPE.A,
                name: 'one.test.lan',
                ttl: 3600,
                address: '127.0.0.1'
            });
            emit({
                class: QCLASS.IN,
                type: QTYPE.A,
                name: 'two.test.lan',
                ttl: 3600,
                address: '127.0.0.2'
            });
            emit({
                class: QCLASS.IN,
                type: QTYPE.A,
                name: 'three.test.lan',
                ttl: 3600,
                address: '127.0.0.3'
            });
            cb(null);
        }
    });
    master.on('error', t.threw);
    return master;
};

const createSlave = (t, cb) => {
    const slave = net.createServer((conn) => {
        conn.on('error', t.threw);
        conn.pipe(concatStream(cb));
    });
    slave.on('error', t.threw);
    return slave;
};

const connect = (t, port, data, cb) => {
    const conn = net.connect(port);
    conn.on('error', t.threw);
    conn.pipe(concatStream(cb));
    conn.end(data);
    return conn;
};

t.test('zone transfer', { timeout: 1000 }, (t) => {
    t.plan(6);

    const axfrReqFixture = readFixture('axfr-request');
    const axfrResFixture = readFixture('axfr-response');

    const master = createMaster(t);
    t.type(master, net.Server, 'instance created');

    master.listen(() => {
        const masterPort = master.address().port;
        t.teardown(() => master.close());

        master.setSlaves(['localhost'], (err) => {
            t.error(err, 'slaves set');

            connect(t, masterPort, axfrReqFixture, (data) => {
                t.same(data, axfrResFixture, 'response received');
            });
        });
    });
});

t.test('notify', { timeout: 1000 }, (t) => {
    t.plan(3);

    const notifyFixture = readFixture('notify');

    const master = createMaster(t);
    t.type(master, net.Server, 'instance created');

    const slave = createSlave(t, (data) => {
        t.same(data, notifyFixture, 'notify received');
    });

    slave.listen(() => {
        const slavePort = slave.address().port;
        t.teardown(() => slave.close());

        master.setSlaves(['localhost@' + slavePort], (err) => {
            t.error(err, 'slaves set');

            master.notify();
        });
    });
});
