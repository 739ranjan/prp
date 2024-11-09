import winston from 'winston';
import path from 'path';
import fs from 'fs';

/**
 *  Define your severity levels.
 * With them, You can create log files,
 * see or hide levels based on the running ENV.
 */
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

/**
 * Set the current severity based on the NODE_ENV.
 */
const level = () => {
  const env = process.env.NODE_ENV || 'development';
  return env === 'development' ? 'debug' : 'warn';
};

/**
 * Define different colors for each level.
 */
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

// Tell winston to use the colors defined
winston.addColors(colors);

// Chose the aspect of your log customizing the log format.
const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
);

// Set log directory path to '/tmp/logs' to comply with Vercel's serverless environment
const logDir = '/tmp/logs';

// Ensure log directory exists
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

// Define which transports the logger must use to print out messages.
const transports = [
  // Print messages to the console with color formatting
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize({ all: true })
    ),
  }),
  // Print error messages to error.log inside /tmp/logs
  new winston.transports.File({
    filename: path.join(logDir, 'error.log'),
    level: 'error',
  }),
  // Print all messages to all.log inside /tmp/logs
  new winston.transports.File({ filename: path.join(logDir, 'all.log') }),
];

// Create the logger instance
const Logger = winston.createLogger({
  level: level(),
  levels,
  format,
  transports,
});

export default Logger;
