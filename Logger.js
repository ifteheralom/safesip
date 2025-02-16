/**
 * Logger.js
 *
 * Provides a Logger class with colorized output, including file and line info.
 */
class Logger {
    static log(level, message) {
      const { fileInfo, lineNumber } = this._getCallerInfo();
      const time = new Date().toISOString().replace('T', ' ').replace('Z','');
  
      let colorFn = (str) => str;
      switch (level) {
        case 'debug': colorFn = (str) => `\x1b[35m${str}\x1b[0m`; break; // magenta
        case 'info':  colorFn = (str) => `\x1b[32m${str}\x1b[0m`; break; // green
        case 'warn':  colorFn = (str) => `\x1b[33m${str}\x1b[0m`; break; // yellow
        case 'error': colorFn = (str) => `\x1b[31m${str}\x1b[0m`; break; // red
        default:      colorFn = (str) => str; break;
      }
  
      const levelTag = level.toUpperCase().padEnd(5);
      const location = `${fileInfo}:${lineNumber}`;
      const finalMsg = `${time} [${levelTag}] [${location}] ${message}`;
      console.log(colorFn(finalMsg));
    }
  
    static debug(msg) { this.log('debug', msg); }
    static info(msg)  { this.log('info',  msg); }
    static warn(msg)  { this.log('warn',  msg); }
    static error(msg) { this.log('error', msg); }
  
    static _getCallerInfo() {
      const obj = {};
      Error.captureStackTrace(obj, this._getCallerInfo);
      const stackLines = obj.stack.split('\n');
      let callerLine = '';
      for (let i = 1; i < stackLines.length; i++) {
        if (!stackLines[i].includes(__filename)) {
          callerLine = stackLines[i].trim();
          break;
        }
      }
      let fileInfo = 'unknown';
      let lineNumber = '??';
      const match = callerLine.match(/\(([^)]+)\)/);
      if (match && match[1]) {
        const parts = match[1].split(':');
        if (parts.length >= 2) {
          fileInfo = parts[0].split('/').pop();
          lineNumber = parts[1];
        }
      }
      return { fileInfo, lineNumber };
    }
  }
  
  module.exports = Logger;
  