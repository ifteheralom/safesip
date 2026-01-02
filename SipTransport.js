const net = require('net');
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
  constructor(localIp, localPort, protocol = 'udp') {
    this.localIp   = localIp;
    this.localPort = localPort;
    this.protocol  = protocol.toLowerCase();
    
    this.socket    = null;
    this.onRequest  = null; 
    this.onResponse = null;
    
    // TCP Stream Buffer
    this.buffer = ''; 
  }

  // Unified start method
  start(serverHost, serverPort, callback) {
    if (this.protocol === 'tcp') {
      this._startTcp(serverHost, serverPort, callback);
    } else {
      this._startUdp(serverHost, serverPort, callback);
    }
  }

  // --------------------------------------------------------
  // UDP Implementation
  // --------------------------------------------------------
  _startUdp(serverHost, serverPort, callback) {
    this.socket = dgram.createSocket('udp4');
    
    this.socket.bind(this.localPort, this.localIp, () => {
      const addr = this.socket.address();
      Logger.info(`SipTransport UDP bound to ${addr.address}:${addr.port}`);
      if (callback) callback(addr.address, addr.port);
    });

    this.socket.on('message', (msg, rinfo) => {
      const text = msg.toString();
      this._processMessage(text, rinfo);
    });

    this.socket.on('error', (err) => {
      Logger.error(`UDP Socket error: ${err}`);
      this.socket.close();
    });
  }

  // --------------------------------------------------------
  // TCP Implementation
  // --------------------------------------------------------
  _startTcp(serverHost, serverPort, callback) {
    this.socket = new net.Socket();

    this.socket.connect(serverPort, serverHost, () => {
      const lAddr = this.socket.address();
      Logger.info(`SipTransport TCP connected to ${serverHost}:${serverPort} from ${lAddr.address}:${lAddr.port}`);
      if (callback) callback(lAddr.address, lAddr.port);
    });

    this.socket.on('error', (err) => {
      Logger.error(`TCP Socket error: ${err}`);
      this.socket.destroy();
    });

    this.socket.on('close', () => {
        Logger.warn('TCP Socket closed');
    });

    this.socket.on('data', (data) => {
      this.buffer += data.toString();
      // TCP framing logic
      while (this.buffer.includes('\r\n\r\n')) {
          const endOfHeaders = this.buffer.indexOf('\r\n\r\n') + 4;
          const headerPart = this.buffer.substring(0, endOfHeaders);
          const clMatch = headerPart.match(/Content-Length:\s*(\d+)/i);
          let bodyLen = 0;
          if (clMatch) bodyLen = parseInt(clMatch[1], 10);
          const totalMsgLen = endOfHeaders + bodyLen;

          if (this.buffer.length >= totalMsgLen) {
              const fullMessage = this.buffer.substring(0, totalMsgLen);
              this.buffer = this.buffer.substring(totalMsgLen);
              // For TCP, rinfo is the connected server
              const rinfo = { address: this.socket.remoteAddress, port: this.socket.remotePort };
              this._processMessage(fullMessage, rinfo);
          } else {
              break;
          }
      }
    });
  }

  // --------------------------------------------------------
  // Shared Processing
  // --------------------------------------------------------
  _processMessage(text, rinfo) {
      Logger.debug(`\n=== INBOUND SIP (${this.protocol.toUpperCase()}) ===\n${text}\n=== END INBOUND ===\n`);
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
  }

  sendPacket(sipMessage, host, port, cb) {
    Logger.debug(`\n=== OUTBOUND SIP (${this.protocol.toUpperCase()}) ===\n${sipMessage}\n=== END OUTBOUND ===\n`);
    
    if (this.protocol === 'tcp') {
      // TCP: Socket is already connected, host/port args are ignored (or used for validation)
      if (!this.socket || this.socket.destroyed) {
         Logger.error("Cannot send: TCP socket is closed");
         if (cb) cb(new Error("Socket closed"));
         return;
      }
      this.socket.write(sipMessage, 'utf-8', (err) => {
        if (err) Logger.error(`TCP send error: ${err}`);
        if (cb) cb(err);
      });
    } else {
      // UDP: Send using dgram
      this.socket.send(sipMessage, port, host, (err) => {
        if (err) Logger.error(`UDP send error: ${err}`);
        if (cb) cb(err);
      });
    }
  }

  close() {
    Logger.warn('SipTransport closing socket...');
    if (this.protocol === 'tcp') {
      if (this.socket) this.socket.end();
    } else {
      if (this.socket) this.socket.close();
    }
  }
}

module.exports = SipTransport;