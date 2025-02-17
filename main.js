const Logger = require('./Logger');
const SipClient = require('./SipClient');

const [,, mode, localPortArg, fromUserArg, ...rest] = process.argv;

if (!mode || !['rcv','send'].includes(mode)) {
  Logger.error(`Usage:
    node main.js rcv <port> <fromUser> <password>
    node main.js send <port> <fromUser> <toUser> "msgBody" <password>`);
  process.exit(1);
}

const localPort = parseInt(localPortArg, 10) || 55090;
const fromUser  = fromUserArg || 'alice';

let toUser  = '';
let msgBody = '';
let password = '';

if (mode === 'rcv') {
  if (rest.length < 1) {
    Logger.error('RCV mode requires <password>');
    process.exit(1);
  }
  password = rest[0]; 

} else {
  if (rest.length < 3) {
    Logger.error('SEND mode requires <toUser> "msgBody" <password>');
    process.exit(1);
  }
  toUser  = rest[0];
  password = rest[rest.length - 1]; 

  if (rest.length < 3) {
    Logger.error('No message body found?');
    process.exit(1);
  }
  msgBody = rest.slice(1, rest.length - 1).join(' ');
}

const client = new SipClient({
  fromUser,
  password,
  localPort,
  toUser,
  messageBody: msgBody,
  mode,
});

client.start();

process.on('SIGINT', () => {
  Logger.warn('SIGINT => closing SipClient');
  client.close();
  process.exit(0);
});
