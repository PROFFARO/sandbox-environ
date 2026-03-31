/**
 * WebSocket Handler
 * 
 * Manages WebSocket connections for real-time execution streaming.
 */

import { WebSocketServer } from 'ws';

let wss = null;
const clients = new Map(); // clientId -> { ws, subscriptions: Set<executionId> }

/**
 * Initialize WebSocket server
 */
export function initWebSocket(server) {
  wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws) => {
    const clientId = Date.now().toString(36) + Math.random().toString(36).substr(2);
    clients.set(clientId, { ws, subscriptions: new Set() });

    // Send welcome message
    ws.send(JSON.stringify({
      type: 'connected',
      clientId,
      message: 'Connected to Sandbox WebSocket'
    }));

    // Handle incoming messages
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        handleClientMessage(clientId, data);
      } catch (e) {
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
      }
    });

    // Handle disconnect
    ws.on('close', () => {
      clients.delete(clientId);
    });

    ws.on('error', () => {
      clients.delete(clientId);
    });
  });

  return wss;
}

/**
 * Handle messages from WebSocket clients
 */
function handleClientMessage(clientId, data) {
  const client = clients.get(clientId);
  if (!client) return;

  switch (data.type) {
    case 'subscribe':
      if (data.executionId) {
        client.subscriptions.add(data.executionId);
        client.ws.send(JSON.stringify({
          type: 'subscribed',
          executionId: data.executionId
        }));
      }
      break;

    case 'unsubscribe':
      if (data.executionId) {
        client.subscriptions.delete(data.executionId);
      }
      break;

    case 'ping':
      client.ws.send(JSON.stringify({ type: 'pong' }));
      break;
  }
}

/**
 * Broadcast an event to all clients subscribed to an execution
 */
export function broadcastEvent(event, data) {
  const executionId = data.executionId;

  for (const [, client] of clients) {
    if (client.ws.readyState === 1) { // WebSocket.OPEN
      // Send to subscribers of this execution or to all (for global events)
      if (!executionId || client.subscriptions.has(executionId) || client.subscriptions.has('*')) {
        try {
          client.ws.send(JSON.stringify({ type: event, ...data }));
        } catch (e) {
          // Client might have disconnected
        }
      }
    }
  }
}

/**
 * Get connected client count
 */
export function getClientCount() {
  return clients.size;
}
