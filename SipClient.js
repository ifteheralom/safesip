const crypto = require('crypto');
const Logger = require('./Logger');
const SipRequestBuilder = require('./SipRequestBuilder');
const SipTransport = require('./SipTransport');
const {
  SIP_SERVER_HOST,
  SIP_SERVER_PORT,
  LOCAL_IP,
  REGISTER_EXPIRES,
  RE_REGISTER_PERIOD,
} = require('./config');

function md5(str) {
  return crypto.createHash('md5').update(str).digest('hex');
}

class SipClient {
  constructor({
    fromUser,
    password,
    localPort,
    toUser = '',
    messageBody = '',
    mode = 'rcv',
    protocol = 'udp', // New Argument
  }) {
    this.fromUser    = fromUser;
    this.password    = password;
    this.localPort   = localPort;
    this.toUser      = toUser;
    this.messageBody = messageBody;
    this.mode        = mode;
    this.protocol    = protocol; // Store protocol

    // Registration state
    this.isRegistered = false;
    this.regCallId  = this._makeCallId('reg');
    this.regBranch  = this._makeBranch();
    this.regFromTag = this._makeTag();
    this.regCseq    = 1;

    // INVITE -> ACK state
    this.inviteCallId  = null;
    this.inviteBranch  = null;
    this.inviteFromTag = null;
    this.inviteCseq    = 1;

    // Pass protocol to Transport
    this.transport = new SipTransport(LOCAL_IP, localPort, this.protocol);
    this.transport.onResponse = (res) => this._handleResponse(res);
    this.transport.onRequest  = (req) => this._handleRequest(req);
  }

  start() {
    // We renamed connect() to start() in SipTransport to be generic
    this.transport.start(SIP_SERVER_HOST, SIP_SERVER_PORT, (actualIp, actualPort) => {
      
      this.localPort = actualPort;
      // this.localIp = actualIp; 

      Logger.info(`SipClient started (${this.protocol.toUpperCase()}). mode="${this.mode}", user="${this.fromUser}"`);
      
      this._sendRegister();

      if (this.mode === 'rcv') {
        this.keepAliveTimer = setInterval(() => {
          Logger.debug('Re-REGISTER keep-alive...');
          this._sendRegister();
        }, RE_REGISTER_PERIOD * 1000);
      } else {
        setTimeout(() => {
          if (!this.isRegistered) {
            Logger.warn('Not yet confirmed REGISTER, sending request anyway...');
          }
          this._sendMessage();
        }, 3000);
      }
    });
  }

  close() {
    if (this.keepAliveTimer) {
      clearInterval(this.keepAliveTimer);
    }
    this.transport.close();
  }

  // ... (Keep _handleResponse, _handleRequest, _build200OkResponse exactly as they are) ...
  // [Copy the existing methods from your file here]
  // Note: Just ensure _handleResponse calls _handleAuthChallenge correctly

  _handleResponse({ statusCode, reason, messageLines }) {
    Logger.debug(`_handleResponse: ${statusCode} ${reason}`);
    const cseqLine = messageLines.find((l) => l.toLowerCase().startsWith('cseq:')) || '';
    const cseqVal  = cseqLine.slice(5).trim().toLowerCase();

    if (statusCode === 401 || statusCode === 407) {
      Logger.warn(`Got ${statusCode}, need auth. Attempting Digest...`);
      const isProxy = (statusCode === 407);
      this._handleAuthChallenge(isProxy, messageLines, cseqVal);
      return;
    }

    if (statusCode >= 200 && statusCode < 300) {
      if (cseqVal.includes('register')) {
        Logger.info('REGISTER => 2xx => we are registered');
        this.isRegistered = true;
      } else if (cseqVal.includes('message')) {
        Logger.info('MESSAGE => 2xx => accepted!');
        if (this.mode === 'send') {
          Logger.info('Closing socket after MESSAGE send.');
          this.close();
        }
      } else if (cseqVal.includes('invite')) {
        Logger.info('INVITE => 2xx => we must ACK');
        this._sendAckForInvite();
      }
    } else {
      Logger.warn(`Non-200 response: ${statusCode} ${reason}`);
      if (this.mode === 'send') {
        Logger.warn('Closing socket on error in "send" mode');
        this.close();
      }
    }
  }

  _handleRequest({ method, messageLines, rinfo }) {
    Logger.info(`Inbound SIP request: ${method} from ${rinfo.address}:${rinfo.port}`);
    const ok = this._build200OkResponse(messageLines);
    this.transport.sendPacket(ok, rinfo.address, rinfo.port, () => {
      Logger.info(`Sent full 200 OK for inbound ${method} request`);
    });
  }

  _build200OkResponse(requestLines) {
    const viaLine = requestLines.filter(line => line.toLowerCase().startsWith('via:'));
    let   fromLine   = requestLines.find(l => l.toLowerCase().startsWith('from:'))    || '';
    let   toLine     = requestLines.find(l => l.toLowerCase().startsWith('to:'))      || '';
    const callIdLine = requestLines.find(l => l.toLowerCase().startsWith('call-id:')) || '';
    const cseqLine   = requestLines.find(l => l.toLowerCase().startsWith('cseq:'))    || '';

    const lines = [
      'SIP/2.0 200 OK',
      ...viaLine, // Spread array in case of multiple Vias
      fromLine,
      toLine,
      callIdLine,
      cseqLine,
      'Server: Node-SIP-Demo',
      'Content-Length: 0',
      '', 
      ''
    ];
    return lines.join('\r\n');
  }

  _sendRegister() {
    this.regBranch = this._makeBranch();
    this.regCseq++;

    const builder = new SipRequestBuilder({
      method: 'REGISTER',
      fromUser: this.fromUser,
      domain: SIP_SERVER_HOST,
      localIp: LOCAL_IP,
      localPort: this.localPort,
      callId: this.regCallId,
      branch: this.regBranch,
      fromTag: this.regFromTag,
      cseqNumber: this.regCseq,
      contactUri: `sip:${this.fromUser}@${LOCAL_IP}:${this.localPort}`,
      expires: REGISTER_EXPIRES,
      protocol: this.protocol, // Pass protocol
    });

    const msg = builder.build();
    Logger.info(`Sending REGISTER (cseq=${this.regCseq})`);
    this.transport.sendPacket(msg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  _sendMessage() {
    const msgCallId  = this._makeCallId('msg');
    const msgBranch  = this._makeBranch();
    const msgFromTag = this._makeTag();

    const builder = new SipRequestBuilder({
      method: 'MESSAGE',
      fromUser: this.fromUser,
      toUser: this.toUser,
      domain: SIP_SERVER_HOST,
      localIp: LOCAL_IP,
      localPort: this.localPort,
      callId: msgCallId,
      branch: msgBranch,
      fromTag: msgFromTag,
      cseqNumber: 1,
      body: this.messageBody,
      protocol: this.protocol, // Pass protocol
    });

    const sipMsg = builder.build();
    Logger.info(`Sending MESSAGE => "${this.messageBody}"`);
    this.transport.sendPacket(sipMsg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  _sendInvite() {
    this.inviteCallId  = this._makeCallId('invite');
    this.inviteBranch  = this._makeBranch();
    this.inviteFromTag = this._makeTag();

    const builder = new SipRequestBuilder({
      method: 'INVITE',
      fromUser: this.fromUser,
      toUser: this.toUser,
      domain: SIP_SERVER_HOST,
      localIp: LOCAL_IP,
      localPort: this.localPort,
      callId: this.inviteCallId,
      branch: this.inviteBranch,
      fromTag: this.inviteFromTag,
      cseqNumber: this.inviteCseq,
      body: '',
      protocol: this.protocol, // Pass protocol
    });

    const inviteMsg = builder.build();
    Logger.info('Sending INVITE...');
    this.transport.sendPacket(inviteMsg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  _sendAckForInvite() {
    const ackBranch = `${this.inviteBranch}-ack`;

    const builder = new SipRequestBuilder({
      method: 'ACK',
      fromUser: this.fromUser,
      toUser: this.toUser,
      domain: SIP_SERVER_HOST,
      localIp: LOCAL_IP,
      localPort: this.localPort,
      callId: this.inviteCallId,
      branch: ackBranch,
      fromTag: this.inviteFromTag,
      cseqNumber: this.inviteCseq,
      protocol: this.protocol, // Pass protocol
    });

    const ackMsg = builder.build();
    Logger.info('Sending ACK for INVITE 2xx...');
    this.transport.sendPacket(ackMsg, SIP_SERVER_HOST, SIP_SERVER_PORT, () => {
      if (this.mode === 'send') {
        Logger.info('Closing socket after INVITE => 200 OK => ACK flow.');
        this.close();
      }
    });
  }

  _handleAuthChallenge(isProxy, lines, cseqVal) {
    const challengeHeader = lines.find((l) => {
      const lower = l.toLowerCase();
      return isProxy
        ? lower.startsWith('proxy-authenticate:')
        : lower.startsWith('www-authenticate:');
    });
    if (!challengeHeader) {
      Logger.error('No auth challenge header found, cannot authenticate');
      return;
    }

    const realmMatch = challengeHeader.match(/realm="([^"]+)"/i);
    const nonceMatch = challengeHeader.match(/nonce="([^"]+)"/i);
    if (!realmMatch || !nonceMatch) {
      Logger.error(`Could not parse realm/nonce from: ${challengeHeader}`);
      return;
    }
    const realm = realmMatch[1];
    const nonce = nonceMatch[1];

    if (cseqVal.includes('register')) {
      this.regCseq++;
      this._sendRegisterWithAuth(realm, nonce, isProxy);
    } else if (cseqVal.includes('message')) {
      this._sendMessageWithAuth(realm, nonce, isProxy);
    } else if (cseqVal.includes('invite')) {
      this.inviteCseq++;
      this._sendInviteWithAuth(realm, nonce, isProxy);
    } else {
      Logger.warn(`Auth challenge for unrecognized cseqVal: ${cseqVal}`);
    }
  }

  _buildDigestAuthHeader({ method, uri, username, password, realm, nonce, isProxy }) {
    const a1 = md5(`${username}:${realm}:${password}`);
    const a2 = md5(`${method.toUpperCase()}:${uri}`);
    const response = md5(`${a1}:${nonce}:${a2}`);
    const authType = isProxy ? 'Proxy-Authorization' : 'Authorization';

    return `${authType}: Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}"`;
  }

  _sendRegisterWithAuth(realm, nonce, isProxy) {
    this.regBranch = this._makeBranch();
    const authHeader = this._buildDigestAuthHeader({
      method: 'REGISTER',
      uri: `sip:${SIP_SERVER_HOST}`,
      username: this.fromUser,
      password: this.password,
      realm, nonce, isProxy,
    });

    const builder = new SipRequestBuilder({
      method: 'REGISTER',
      fromUser: this.fromUser,
      domain: SIP_SERVER_HOST,
      localIp: LOCAL_IP,
      localPort: this.localPort,
      callId: this.regCallId,
      branch: this.regBranch,
      fromTag: this.regFromTag,
      cseqNumber: this.regCseq,
      contactUri: `sip:${this.fromUser}@${LOCAL_IP}:${this.localPort}`,
      expires: REGISTER_EXPIRES,
      authHeader,
      protocol: this.protocol,
    });

    const msg = builder.build();
    this.transport.sendPacket(msg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  _sendMessageWithAuth(realm, nonce, isProxy) {
    const msgCallId  = this._makeCallId('msg2');
    const msgBranch  = this._makeBranch();
    const msgFromTag = this._makeTag();

    const authHeader = this._buildDigestAuthHeader({
      method: 'MESSAGE',
      uri: `sip:${this.toUser}@${SIP_SERVER_HOST}`,
      username: this.fromUser,
      password: this.password,
      realm, nonce, isProxy,
    });

    const builder = new SipRequestBuilder({
      method: 'MESSAGE',
      fromUser: this.fromUser,
      toUser:   this.toUser,
      domain:   SIP_SERVER_HOST,
      localIp:  LOCAL_IP,
      localPort:this.localPort,
      callId:   msgCallId,
      branch:   msgBranch,
      fromTag:  msgFromTag,
      cseqNumber: 2,
      body: this.messageBody,
      authHeader,
      protocol: this.protocol,
    });

    const msg = builder.build();
    this.transport.sendPacket(msg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  _sendInviteWithAuth(realm, nonce, isProxy) {
    this.inviteBranch = this._makeBranch();

    const authHeader = this._buildDigestAuthHeader({
      method: 'INVITE',
      uri: `sip:${this.toUser}@${SIP_SERVER_HOST}`,
      username: this.fromUser,
      password: this.password,
      realm, nonce, isProxy,
    });

    const builder = new SipRequestBuilder({
      method: 'INVITE',
      fromUser: this.fromUser,
      toUser:   this.toUser,
      domain:   SIP_SERVER_HOST,
      localIp:  LOCAL_IP,
      localPort:this.localPort,
      callId:   this.inviteCallId,
      branch:   this.inviteBranch,
      fromTag:  this.inviteFromTag,
      cseqNumber: this.inviteCseq,
      body: '',
      authHeader,
      protocol: this.protocol,
    });

    const msg = builder.build();
    this.transport.sendPacket(msg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  // ... (Keep _makeCallId, _makeBranch, _makeTag) ...
  _makeCallId(prefix) { return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 10000)}`; }
  _makeBranch() { return `z9hG4bK-${Math.floor(Math.random() * 1000000)}`; }
  _makeTag() { return `tag-${Math.floor(Math.random() * 1000000)}`; }
}

module.exports = SipClient;