const Logger = require('./Logger');

class SipRequestBuilder {
  constructor({
    method,
    fromUser,
    toUser,
    domain,
    localIp,
    localPort,
    callId,
    branch,
    fromTag,
    cseqNumber,
    body,
    contactUri,
    expires,
    contentType,
    authHeader,
  }) {
    Logger.debug(`SipRequestBuilder: method=${method}, from=${fromUser}, to=${toUser}`);

    this.method      = method.toUpperCase();
    this.fromUser    = fromUser;
    this.toUser      = toUser;
    this.domain      = domain;
    this.localIp     = localIp;
    this.localPort   = localPort;
    this.callId      = callId;
    this.branch      = branch;
    this.fromTag     = fromTag;
    this.cseqNumber  = cseqNumber;
    this.body        = body || '';
    this.contactUri  = contactUri;
    this.expires     = expires;
    this.contentType = contentType || 'text/plain';
    this.authHeader  = authHeader || null;
  }

  build() {
    const viaHeader    = `Via: SIP/2.0/UDP ${this.localIp}:${this.localPort};branch=${this.branch}`;
    const fromHeader   = `From: <sip:${this.fromUser}@${this.domain}>;tag=${this.fromTag}`;
    const callIdHeader = `Call-ID: ${this.callId}`;
    const cseqHeader   = `CSeq: ${this.cseqNumber} ${this.method}`;
    const maxForwards  = `Max-Forwards: 70`;

    const bodyContent  = this.body;
    let length         = bodyContent.length; // number of bytes in the body

    // Headers array
    let lines = [];

    switch (this.method) {
      case 'REGISTER': {
        lines = [
          `${this.method} sip:${this.domain} SIP/2.0`,
          viaHeader,
          maxForwards,
          `To: <sip:${this.fromUser}@${this.domain}>`,
          fromHeader,
          callIdHeader,
          cseqHeader,
          `Contact: <${this.contactUri}>`,
          `Expires: ${this.expires}`,
          `User-Agent: Node-SIP-Demo`,
          `Content-Length: ${length}`
        ];
        break;
      }

      case 'MESSAGE': {
        const contentTypeHeader = `Content-Type: ${this.contentType}`;
        lines = [
          `${this.method} sip:${this.toUser}@${this.domain} SIP/2.0`,
          viaHeader,
          maxForwards,
          `To: <sip:${this.toUser}@${this.domain}>`,
          fromHeader,
          callIdHeader,
          cseqHeader,
          contentTypeHeader,
          `Content-Length: ${length}`
        ];
        break;
      }

      case 'INVITE': {
        const contentTypeHeader = `Content-Type: application/sdp`; 
        lines = [
          `${this.method} sip:${this.toUser}@${this.domain} SIP/2.0`,
          viaHeader,
          maxForwards,
          `To: <sip:${this.toUser}@${this.domain}>`,
          fromHeader,
          callIdHeader,
          cseqHeader,
          `Contact: <sip:${this.fromUser}@${this.localIp}:${this.localPort}>`,
          contentTypeHeader,
          `Content-Length: ${length}`
        ];
        break;
      }

      case 'ACK': {
        length = 0; 
        lines = [
          `${this.method} sip:${this.toUser}@${this.domain} SIP/2.0`,
          viaHeader,
          maxForwards,
          `To: <sip:${this.toUser}@${this.domain}>`,
          fromHeader,
          callIdHeader,
          `CSeq: ${this.cseqNumber} ACK`,
          `Content-Length: 0`
        ];
        break;
      }

      default:
        throw new Error(`Unknown method: ${this.method}`);
    }

    // Insert Authorization/Proxy-Authorization if present
    if (this.authHeader) {
      const cseqIndex = lines.findIndex((l) => l.toLowerCase().startsWith('cseq:'));
      if (cseqIndex >= 0) {
        lines.splice(cseqIndex + 1, 0, this.authHeader);
      } else {
        lines.push(this.authHeader);
      }
    }

    // single blank line after the last header line
    lines.push('');

    // then the body (even if empty, as you indicated this code "works")
    lines.push(bodyContent);

    // Join all lines with CRLF
    // This does NOT add an extra blank line at the end. 
    const message = lines.join('\r\n');

    // The final SIP message might look like:
    //   REGISTER sip:testsip SIP/2.0\r\n
    //   Via: ...
    //   ...
    //   Content-Length: 10\r\n
    //   \r\n
    //   <body> (which might be empty)
    return message;
  }
}

module.exports = SipRequestBuilder;
