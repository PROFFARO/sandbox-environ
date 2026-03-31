/**
 * Controlled Execution Sandbox — Server Entry Point
 * 
 * Express + WebSocket server that provides the sandbox API.
 */

import express from 'express';
import cors from 'cors';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import { getDatabase, closeDatabase } from './database/schema.js';
import { initWebSocket } from './websocket/handler.js';
import executionRoutes from './routes/execution.js';
import policyRoutes from './routes/policies.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3001;

async function start() {
  // Initialize database
  console.log('🗄️  Initializing database...');
  await getDatabase();
  console.log('✅ Database ready');

  // Create Express app
  const app = express();

  // Middleware
  app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:4173'],
    credentials: true
  }));
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true }));

  // API Routes
  app.use('/api', executionRoutes);
  app.use('/api/policies', policyRoutes);

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
  });

  // Serve static files in production
  const clientDist = path.join(__dirname, '..', '..', 'client', 'dist');
  app.use(express.static(clientDist));
  app.get('*', (req, res) => {
    if (!req.path.startsWith('/api') && !req.path.startsWith('/ws')) {
      res.sendFile(path.join(clientDist, 'index.html'));
    }
  });

  // Create HTTP server
  const server = http.createServer(app);

  // Initialize WebSocket
  console.log('🔌 Initializing WebSocket server...');
  initWebSocket(server);
  console.log('✅ WebSocket ready');

  // Start server
  server.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════════════╗');
    console.log('║     🔒 Controlled Execution Sandbox Server 🔒       ║');
    console.log('╠══════════════════════════════════════════════════════╣');
    console.log(`║  🌐 HTTP:      http://localhost:${PORT}               ║`);
    console.log(`║  🔌 WebSocket: ws://localhost:${PORT}/ws              ║`);
    console.log(`║  📊 API:       http://localhost:${PORT}/api           ║`);
    console.log('╚══════════════════════════════════════════════════════╝');
    console.log('');
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log('\n🛑 Shutting down...');
    closeDatabase();
    server.close(() => {
      console.log('✅ Server closed');
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

start().catch(err => {
  console.error('❌ Failed to start server:', err);
  process.exit(1);
});
