/**
 * SipClient.js
 *
 * A refactored, more readable version of the SIP client class.
 * It orchestrates:
 *   - Registration & re-REGISTER keep-alive
 *   - Digest Authentication on 401/407
 *   - Sending MESSAGE or INVITE (plus ACK)
 *   - Inbound request handling (respond 200 OK)
 *   - Ties into SipTransport and SipRequestBuilder
 */

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
    // Basic info
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

  /**
   * Start the client: bind the socket, do initial REGISTER,
   * and if in "rcv" mode keep re-registering.
   * If in "send" mode, send MESSAGE or INVITE after a short delay.
   */
  start() {
    this.transport.bind(() => {
      Logger.info(`SipClient started. mode="${this.mode}", user="${this.fromUser}", pass="${this.password}"`);
      // 1) REGISTER
      this._sendRegister();

      if (this.mode === 'rcv') {
        // Periodic keep-alive re-REGISTER
        this.keepAliveTimer = setInterval(() => {
          Logger.debug('Re-REGISTER keep-alive...');
          this._sendRegister();
        }, RE_REGISTER_PERIOD * 1000);
      } else {
        // "send" mode => after a small delay, send MESSAGE or INVITE
        setTimeout(() => {
          if (!this.isRegistered) {
            Logger.warn('Not yet confirmed REGISTER, sending request anyway...');
          }
          // By default, we do MESSAGE. You can switch to INVITE if needed.
          this._sendMessage();
          // Or: this._sendInvite();
        }, 3000);
      }
    });
  }

  /**
   * Gracefully close the client: clear keep-alive, close socket.
   */
  close() {
    if (this.keepAliveTimer) {
      clearInterval(this.keepAliveTimer);
    }
    this.transport.close();
  }

  // ----------------------------------------------------------------
  //  Private / Internal Methods
  // ----------------------------------------------------------------

  /**
   * Called when we receive a SIP response (onResponse).
   */
  _handleResponse({ statusCode, reason, messageLines }) {
    Logger.debug(`_handleResponse: ${statusCode} ${reason}`);
    const cseqLine = messageLines.find((l) => l.toLowerCase().startsWith('cseq:')) || '';
    const cseqVal  = cseqLine.slice(5).trim().toLowerCase();

    // Auth challenge?
    if (statusCode === 401 || statusCode === 407) {
      Logger.warn(`Got ${statusCode}, need auth. Attempting Digest...`);
      const isProxy = (statusCode === 407);
      this._handleAuthChallenge(isProxy, messageLines, cseqVal);
      return;
    }

    // 2xx success
    if (statusCode >= 200 && statusCode < 300) {
      if (cseqVal.includes('register')) {
        Logger.info('REGISTER => 2xx => we are registered');
        this.isRegistered = true;

      } else if (cseqVal.includes('message')) {
        Logger.info('MESSAGE => 2xx => accepted!');
        // "send" mode => close socket
        if (this.mode === 'send') {
          Logger.info('Closing socket after MESSAGE send.');
          this.close();
        }

      } else if (cseqVal.includes('invite')) {
        Logger.info('INVITE => 2xx => we must ACK');
        this._sendAckForInvite();
      }
    } else {
      // Non-200 error
      Logger.warn(`Non-200 response: ${statusCode} ${reason}`);
      if (this.mode === 'send') {
        Logger.warn('Closing socket on error in "send" mode');
        this.close();
      }
    }
  }

  /**
   * Called when we receive a SIP request (onRequest).
   */
  _handleRequest({ method, messageLines, rinfo }) {
    Logger.info(`Inbound SIP request: ${method} from ${rinfo.address}:${rinfo.port}`);
    if (method === 'MESSAGE') {
      // Return 200 OK
      const ok = this._build200Ok(messageLines);
      this.transport.sendPacket(ok, rinfo.address, rinfo.port, () => {
        Logger.info('Sent 200 OK for inbound MESSAGE');
      });

    } else if (method === 'INVITE') {
      // Minimal 200 OK for INVITE
      const ok = this._buildInvite200Ok(messageLines);
      this.transport.sendPacket(ok, rinfo.address, rinfo.port, () => {
        Logger.info('Sent 200 OK for inbound INVITE => expect ACK from caller');
      });

    } else {
      // Return 200 OK for unhandled method
      const ok = this._build200Ok(messageLines);
      this.transport.sendPacket(ok, rinfo.address, rinfo.port);
    }
  }

  // ----------------------------------------------------------------
  //  Registration / Keep-alive
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
      // No body => content-length=0
    });

    const msg = builder.build();
    Logger.info(`Sending REGISTER (cseq=${this.regCseq})`);
    this.transport.sendPacket(msg, SIP_SERVER_HOST, SIP_SERVER_PORT);
  }

  // ----------------------------------------------------------------
  //  MESSAGE
  // ----------------------------------------------------------------

  _sendMessage() {
    // Build a new call-id, branch, from-tag for each message
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
  //  INVITE -> ACK
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
      body: '', // minimal or empty body
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
      cseqNumber: this.inviteCseq, // same as INVITE cseq
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
  //  Helpers for building 200 OK responses
  // ----------------------------------------------------------------

  _build200Ok(lines) {
    const viaLine    = lines.find(l => l.toLowerCase().startsWith('via:'))     || '';
    const callIdLine = lines.find(l => l.toLowerCase().startsWith('call-id:')) || '';
    const fromLine   = lines.find(l => l.toLowerCase().startsWith('from:'))    || '';
    let   toLine     = lines.find(l => l.toLowerCase().startsWith('to:'))      || '';
    const cseqLine   = lines.find(l => l.toLowerCase().startsWith('cseq:'))    || '';

    if (!/tag\s*=\S+/i.test(toLine)) {
      toLine = toLine.replace(/>$/, `;tag=${Math.floor(Math.random() * 9999)}>`);
    }

    return [
      'SIP/2.0 200 OK',
      viaLine,
      toLine,
      fromLine,
      callIdLine,
      cseqLine,
      'Content-Length: 0',
      '',
      ''
    ].join('\r\n');
  }

  _buildInvite200Ok(lines) {
    // Could add Contact or SDP for a real call flow. Minimal 200 OK here.
    return this._build200Ok(lines);
  }

  // ----------------------------------------------------------------
  //  Utility
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
