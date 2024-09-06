#!/usr/bin/env node

/**
 * Module dependencies.
 */

var app = require('../app');
var debug = require('debug')('challange-chapter-7:server');
var http = require('http');
var {Server} = require('socket.io');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

//require dotenv
require("dotenv").config();
/**
 * Get port from environment and store in Express.
 */

var port = normalizePort(process.env.PORT || '3000');
app.set('port', port);

/**
 * Create HTTP server.
 */

var server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
  }
});

// const clients = {}


io.use((socket, next) => {
  const id_user = socket.handshake.query.id_user;
  if (!id_user) {
    return next(new Error('id_user is required'));
  }

  socket.id_user = id_user;
  next();
});

io.on('connection', async (socket) => {

  console.log(`a user connected: ${socket.id}`);

  // Update table user socket_id with socket.id
  await prisma.user.update({
    where: {
      id: socket.id_user,
    },
    data: {
      socket_id: socket.id,
    },
  });

  socket.on('new-notification', async ({ recipientId, message }) => {

    // Find the socket id of the recipient
    const recipient = await prisma.user.findFirst({
      where: {
        id: recipientId,
      }
    });

    if (recipient) {
      io.to(recipient.socket_id).emit('new-notification', {
        message,
      });
    }
  });



  socket.on('disconnect', () => {
    // delete clients[socket.id];
    console.log('user disconnected');
    // io.emit('client-disconnected', socket.id);
  });
});

/**
 * Listen on provided port, on all network interfaces.
 */

server.listen(port);
server.on('error', onError);
server.on('listening', onListening);

/**
 * Normalize a port into a number, string, or false.
 */

function normalizePort(val) {
  var port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}

/**
 * Event listener for HTTP server "error" event.
 */

function onError(error) {
  if (error.syscall !== 'listen') {
    throw error;
  }

  var bind = typeof port === 'string'
    ? 'Pipe ' + port
    : 'Port ' + port;

  // handle specific listen errors with friendly messages
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
}

/**
 * Event listener for HTTP server "listening" event.
 */

function onListening() {
  var addr = server.address();
  var bind = typeof addr === 'string'
    ? 'pipe ' + addr
    : 'port ' + addr.port;
  console.log('Listening on ' + bind);
}