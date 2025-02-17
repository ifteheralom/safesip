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
  }) {
    this.fromUser    = fromUser;
    this.password    = password;
    this.localPort   = localPort;
    this.toUser      = toUser;
    this.messageBody = messageBody;
    this.mode        = mode;

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

    // Create transport, set callbacks
    this.transport = new SipTransport(LOCAL_IP, localPort);
    this.transport.onResponse = (res) => this._handleResponse(res);
    this.transport.onRequest  = (req) => this._handleRequest(req);
  }

  start() {
    // Bind, send REGISTER, keep alive if rcv, or send request if send mode
    this.transport.bind(() => {
      Logger.info(`SipClient started. mode="${this.mode}", user="${this.fromUser}", pass="${this.password}"`);
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
          // Default: send MESSAGE. (Or _sendInvite if you prefer)
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

  // ----------------------------------------------------------------
  // Handle Outbound Responses
  // ----------------------------------------------------------------

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

  // ----------------------------------------------------------------
  // Handle Inbound Requests
  // ----------------------------------------------------------------

  _handleRequest({ method, messageLines, rinfo }) {
    Logger.info(`Inbound SIP request: ${method} from ${rinfo.address}:${rinfo.port}`);

    // We'll respond with a single "full" 200 OK for all methods
    // If it's INVITE, you can add a Contact or body if desired
    const ok = this._build200OkResponse(messageLines);
    // console.log(ok)

    this.transport.sendPacket(ok, rinfo.address, rinfo.port, () => {
      Logger.info(`Sent full 200 OK for inbound ${method} request`);
    });
  }

  /**
   * Build a single "full" 200 OK. 
   * Skips angle bracket logic; we just parse from/to, ensure the 'To' has a tag.
   * Also includes "Server: Node-SIP-Demo".
   */
  _build200OkResponse(requestLines) {
    console.log(requestLines)
    console.log(requestLines.find(l => l.toLowerCase().startsWith('via:')))
    const viaLine    = requestLines.find(l => l.toLowerCase().startsWith('via:'))     || '';
    // const viaLine    = `Via: SIP/2.0/UDP ${this.localIp}:${this.localPort};branch=${this.branch}`;
    // const viaLine = requestLines.filter((line) => {
    //   const lower = line.toLowerCase();
    //   return lower.startsWith('via:') && lower.includes('rport');
    // });

    let   fromLine   = requestLines.find(l => l.toLowerCase().startsWith('from:'))    || '';
    let   toLine     = requestLines.find(l => l.toLowerCase().startsWith('to:'))      || '';
    const callIdLine = requestLines.find(l => l.toLowerCase().startsWith('call-id:')) || '';
    const cseqLine   = requestLines.find(l => l.toLowerCase().startsWith('cseq:'))    || '';

    // If "To:" has no tag, add one
    // if (!/tag\s*=\S+/i.test(toLine)) {
    //   toLine = `${toLine};tag=${Math.floor(Math.random() * 9999)}`;
    // }

    const lines = [
      'SIP/2.0 200 OK',
      viaLine,
      fromLine,
      toLine,
      callIdLine,
      cseqLine,
      'Server: Node-SIP-Demo',
      'Content-Length: 0',
      '', // blank line
      ''
    ];
    return lines.join('\r\n');
  }

  // ----------------------------------------------------------------
  // Registration / Keep-alive
  // ----------------------------------------------------------------

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
    });

    const msg = builder.build();
    Logger.info(`Sending REGISTER (cseq=${this.regCseq})`);
    this.transport.sendPacket(msg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  // ----------------------------------------------------------------
  // MESSAGE
  // ----------------------------------------------------------------

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
    });

    const sipMsg = builder.build();
    Logger.info(`Sending MESSAGE => "${this.messageBody}"`);
    this.transport.sendPacket(sipMsg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  // ----------------------------------------------------------------
  // INVITE -> ACK
  // ----------------------------------------------------------------

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

  // ----------------------------------------------------------------
  //  Authentication (401/407)
  // ----------------------------------------------------------------

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
    });

    const msg = builder.build();
    this.transport.sendPacket(msg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  // ----------------------------------------------------------------
  // Utility
  // ----------------------------------------------------------------

  _makeCallId(prefix) {
    return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
  }

  _makeBranch() {
    return `z9hG4bK-${Math.floor(Math.random() * 1000000)}`;
  }

  _makeTag() {
    return `tag-${Math.floor(Math.random() * 1000000)}`;
  }
}

module.exports = SipClient;
