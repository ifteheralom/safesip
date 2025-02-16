/**
 * SipTransport.js
 */
const dgram = require('dgram');
const Logger = require('./Logger');

function parseSipFirstLine(line) {
  if (line.startsWith('SIP/2.0 ')) {
    const parts = line.split(' ');
    return {
      isResponse: true,
      statusCode: parseInt(parts[1], 10),
      reason: parts.slice(2).join(' '),
    };
  } else {
    const parts = line.split(' ');
    return {
      isResponse: false,
      method: parts[0].toUpperCase(),
    };
  }
}

class SipTransport {
  constructor(localIp, localPort) {
    this.localIp   = localIp;
    this.localPort = localPort;
    this.socket    = dgram.createSocket('udp4');

    // Set externally
    this.onRequest  = null; 
    this.onResponse = null;
  }

  bind(callback) {
    this.socket.bind(this.localPort, this.localIp, () => {
      Logger.info(`SipTransport bound to ${this.localIp}:${this.localPort}`);
      if (callback) callback();
    });

    this.socket.on('error', (err) => {
      Logger.error(`Socket error: ${err}`);
      this.socket.close();
    });

    this.socket.on('message', (msg, rinfo) => {
      const text  = msg.toString();
      Logger.debug(`\n=== INBOUND SIP from ${rinfo.address}:${rinfo.port} ===\n${text}\n=== END INBOUND ===\n`);
      const lines = text.split('\r\n').filter(Boolean);
      if (!lines.length) return;

      const firstLine = lines[0];
      const parsed = parseSipFirstLine(firstLine);

      if (parsed.isResponse) {
        this.onResponse?.({
          statusCode: parsed.statusCode,
          reason: parsed.reason,
          messageLines: lines,
          rinfo
        });
      } else {
        this.onRequest?.({
          method: parsed.method,
          messageLines: lines,
          rinfo,
        });
      }
    });
  }

  sendPacket(sipMessage, host, port, cb) {
    Logger.debug(`\n=== OUTBOUND SIP to ${host}:${port} ===\n${sipMessage}\n=== END OUTBOUND ===\n`);
    const buf = Buffer.from(sipMessage, 'utf-8');
    this.socket.send(buf, 0, buf.length, port, host, (err) => {
      if (err) Logger.error(`sendPacket error: ${err}`);
      if (cb) cb(err);
    });
  }

  close() {
    Logger.warn('SipTransport closing socket...');
    this.socket.close();
  }
}

module.exports = SipTransport;
