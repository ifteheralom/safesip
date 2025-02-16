/**
 * main.js
 *
 * Minimal code:
 *  - Parse CLI
 *  - Create a SipClient
 *  - Start the client
 *  - On SIGINT, close
 */

const Logger = require('./Logger');
const SipClient = require('./SipClient');

const [,, mode, localPortArg, fromUserArg, toUserArg, ...rest] = process.argv;

if (!mode || !['rcv','send'].includes(mode)) {
  Logger.error('Usage:\n  node main.js rcv <port> <fromUser> <password>\n  node main.js send <port> <fromUser> <toUser> "msg" <password>');
  process.exit(1);
}

const localPort = parseInt(localPortArg, 10) || 55090;
const fromUser  = fromUserArg || 'alice';
let toUser  = '';
let msgBody = '';
let password = '';

if (mode === 'rcv') {
  if (!rest.length) {
    Logger.error('RCV mode requires <password>');
    process.exit(1);
  }
  password = rest[0];
} else {
  // send mode
  if (!toUserArg) {
    Logger.error('SEND mode requires <toUser> "msgBody" <password>');
    process.exit(1);
  }
  if (rest.length < 1) {
    Logger.error('Missing messageBody or password');
    process.exit(1);
  }
  password = rest[rest.length - 1];
  if (rest.length < 2) {
    Logger.error('No message body found?');
    process.exit(1);
  }
  msgBody = rest.slice(0, rest.length - 1).join(' ');
  toUser  = toUserArg;
}

// Create the client
const client = new SipClient({
  fromUser,
  password,
  localPort,
  toUser,
  messageBody: msgBody,
  mode,
});

// Start
client.start();

// Graceful shutdown on Ctrl+C
process.on('SIGINT', () => {
  Logger.warn('SIGINT => closing SipClient');
  client.close();
  process.exit(0);
});
