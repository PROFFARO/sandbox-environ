/**
 * Execution API Routes
 * 
 * Handles code submission, execution history, and result retrieval.
 * Supports multiple input methods: paste, file upload, URL fetch, Gist import.
 */

import { Router } from 'express';
import multer from 'multer';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { executeCode } from '../sandbox/executionManager.js';
import { getExecution, listExecutions, deleteExecution, getStats } from '../sandbox/executionLogger.js';
import { analyzeCode } from '../sandbox/staticAnalyzer.js';
import { broadcastEvent } from '../websocket/handler.js';

const router = Router();

// Configure multer for file uploads
const uploadDir = path.join(os.tmpdir(), 'sandbox-uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}${path.extname(file.originalname)}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 1024 * 100, // 100KB max file size
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowedExtensions = ['.py', '.js', '.sh', '.txt', '.bash'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedExtensions.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`File type '${ext}' not allowed. Allowed: ${allowedExtensions.join(', ')}`));
    }
  }
});

// Map file extensions to languages
const extToLanguage = {
  '.py': 'python',
  '.js': 'javascript',
  '.sh': 'bash',
  '.bash': 'bash',
  '.txt': null // requires manual language selection
};

// ============================================================
// POST /api/execute — Submit code for execution
// ============================================================
router.post('/execute', async (req, res) => {
  try {
    const { code, language, inputMethod = 'paste', inputSource = null, timeout, memoryLimit } = req.body;

    if (!code || !code.trim()) {
      return res.status(400).json({ error: 'Code is required' });
    }

    if (!language || !['python', 'javascript', 'bash'].includes(language.toLowerCase())) {
      return res.status(400).json({ error: 'Language must be one of: python, javascript, bash' });
    }

    // Execute through sandbox pipeline with WebSocket broadcasting
    const result = await executeCode(
      {
        code: code.trim(),
        language: language.toLowerCase(),
        inputMethod,
        inputSource,
        filename: null,
        timeoutMs: timeout ? Math.min(parseInt(timeout), 30000) : undefined,
        memoryLimitMb: memoryLimit ? Math.min(parseInt(memoryLimit), 256) : undefined,
      },
      (event, data) => {
        broadcastEvent(event, data);
      }
    );

    res.json(result);
  } catch (err) {
    console.error('Execute error:', err);
    res.status(500).json({ error: 'Execution failed: ' + err.message });
  }
});

// ============================================================
// POST /api/execute/upload — Execute from file upload
// ============================================================
router.post('/execute/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const ext = path.extname(req.file.originalname).toLowerCase();
    let language = req.body.language || extToLanguage[ext];

    if (!language) {
      return res.status(400).json({ error: 'Could not determine language. Please specify the language parameter.' });
    }

    // Read file contents
    const code = fs.readFileSync(req.file.path, 'utf8');

    // Clean up uploaded file
    try { fs.unlinkSync(req.file.path); } catch (e) { /* ignore */ }

    if (!code.trim()) {
      return res.status(400).json({ error: 'File is empty' });
    }

    const result = await executeCode(
      {
        code: code.trim(),
        language: language.toLowerCase(),
        inputMethod: 'file_upload',
        inputSource: req.file.originalname,
        filename: req.file.originalname,
        timeoutMs: req.body.timeout ? Math.min(parseInt(req.body.timeout), 30000) : undefined,
        memoryLimitMb: req.body.memoryLimit ? Math.min(parseInt(req.body.memoryLimit), 256) : undefined,
      },
      (event, data) => {
        broadcastEvent(event, data);
      }
    );

    res.json(result);
  } catch (err) {
    console.error('Upload execute error:', err);
    res.status(500).json({ error: 'Execution failed: ' + err.message });
  }
});

// ============================================================
// POST /api/execute/url — Execute from URL (raw file, pastebin, etc.)
// ============================================================
router.post('/execute/url', async (req, res) => {
  try {
    const { url, language } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    // Validate URL
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (e) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Only allow HTTP(S)
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: 'Only HTTP and HTTPS URLs are allowed' });
    }

    // Transform known URLs to raw format
    let fetchUrl = url;
    
    // GitHub: convert blob URLs to raw
    if (parsedUrl.hostname === 'github.com' && url.includes('/blob/')) {
      fetchUrl = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/');
    }
    
    // Pastebin: convert to raw
    if (parsedUrl.hostname === 'pastebin.com' && !url.includes('/raw/')) {
      const pastebinId = parsedUrl.pathname.split('/').pop();
      fetchUrl = `https://pastebin.com/raw/${pastebinId}`;
    }

    // GitHub Gist: convert to raw
    if (parsedUrl.hostname === 'gist.github.com') {
      fetchUrl = url + '/raw';
    }

    // GitLab: convert to raw
    if (url.includes('gitlab.com') && url.includes('/blob/')) {
      fetchUrl = url.replace('/blob/', '/raw/');
    }

    // Fetch the content
    const controller = new AbortController();
    const fetchTimeout = setTimeout(() => controller.abort(), 10000);

    let response;
    try {
      response = await fetch(fetchUrl, {
        signal: controller.signal,
        headers: { 'User-Agent': 'ControlledSandbox/1.0' },
      });
    } catch (fetchErr) {
      clearTimeout(fetchTimeout);
      return res.status(400).json({ error: `Failed to fetch URL: ${fetchErr.message}` });
    }
    clearTimeout(fetchTimeout);

    if (!response.ok) {
      return res.status(400).json({ error: `URL returned status ${response.status}: ${response.statusText}` });
    }

    // Check content type
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('text/html') && !url.includes('pastebin') && !url.includes('gist')) {
      return res.status(400).json({ 
        error: 'URL returned HTML content. Please use a raw/direct link to the source code file.' 
      });
    }

    const code = await response.text();

    if (!code.trim()) {
      return res.status(400).json({ error: 'URL returned empty content' });
    }

    if (code.length > 50000) {
      return res.status(400).json({ error: 'Content exceeds maximum size of 50KB' });
    }

    // Auto-detect language from URL if not provided
    let detectedLang = language;
    if (!detectedLang) {
      const urlPath = parsedUrl.pathname.toLowerCase();
      if (urlPath.endsWith('.py')) detectedLang = 'python';
      else if (urlPath.endsWith('.js')) detectedLang = 'javascript';
      else if (urlPath.endsWith('.sh') || urlPath.endsWith('.bash')) detectedLang = 'bash';
    }

    if (!detectedLang) {
      return res.status(400).json({ 
        error: 'Could not auto-detect language from URL. Please specify the language parameter.' 
      });
    }

    const result = await executeCode(
      {
        code: code.trim(),
        language: detectedLang.toLowerCase(),
        inputMethod: 'url_fetch',
        inputSource: url,
        filename: path.basename(parsedUrl.pathname) || 'remote-file',
        timeoutMs: req.body.timeout ? Math.min(parseInt(req.body.timeout), 30000) : undefined,
        memoryLimitMb: req.body.memoryLimit ? Math.min(parseInt(req.body.memoryLimit), 256) : undefined,
      },
      (event, data) => {
        broadcastEvent(event, data);
      }
    );

    res.json(result);
  } catch (err) {
    console.error('URL execute error:', err);
    res.status(500).json({ error: 'Execution failed: ' + err.message });
  }
});

// ============================================================
// POST /api/execute/gist — Execute from GitHub Gist
// ============================================================
router.post('/execute/gist', async (req, res) => {
  try {
    const { gistUrl, language, filename: targetFile } = req.body;

    if (!gistUrl) {
      return res.status(400).json({ error: 'GitHub Gist URL is required' });
    }

    // Extract Gist ID
    let gistId;
    try {
      const parsed = new URL(gistUrl);
      if (!parsed.hostname.includes('gist.github.com') && !parsed.hostname.includes('api.github.com')) {
        return res.status(400).json({ error: 'URL must be a GitHub Gist URL' });
      }
      gistId = parsed.pathname.split('/').filter(Boolean).pop();
    } catch (e) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Fetch Gist via API
    const apiUrl = `https://api.github.com/gists/${gistId}`;
    const controller = new AbortController();
    const fetchTimeout = setTimeout(() => controller.abort(), 10000);

    let response;
    try {
      response = await fetch(apiUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'ControlledSandbox/1.0',
          'Accept': 'application/vnd.github.v3+json'
        },
      });
    } catch (fetchErr) {
      clearTimeout(fetchTimeout);
      return res.status(400).json({ error: `Failed to fetch Gist: ${fetchErr.message}` });
    }
    clearTimeout(fetchTimeout);

    if (!response.ok) {
      return res.status(400).json({ error: `GitHub API returned status ${response.status}` });
    }

    const gist = await response.json();
    const files = gist.files;

    if (!files || Object.keys(files).length === 0) {
      return res.status(400).json({ error: 'Gist contains no files' });
    }

    // Select file — prefer specified filename, else first file
    let selectedFile;
    if (targetFile && files[targetFile]) {
      selectedFile = files[targetFile];
    } else {
      // Pick the first file
      selectedFile = Object.values(files)[0];
    }

    if (!selectedFile.content) {
      return res.status(400).json({ error: 'Selected Gist file has no content' });
    }

    // Detect language
    let detectedLang = language;
    if (!detectedLang) {
      const ext = path.extname(selectedFile.filename).toLowerCase();
      detectedLang = extToLanguage[ext];
      
      // Try by language field from GitHub
      if (!detectedLang && selectedFile.language) {
        const langMap = { 'Python': 'python', 'JavaScript': 'javascript', 'Shell': 'bash', 'Bash': 'bash' };
        detectedLang = langMap[selectedFile.language];
      }
    }

    if (!detectedLang) {
      return res.status(400).json({
        error: `Could not detect language for '${selectedFile.filename}'. Please specify the language parameter.`,
        availableFiles: Object.keys(files)
      });
    }

    const result = await executeCode(
      {
        code: selectedFile.content.trim(),
        language: detectedLang.toLowerCase(),
        inputMethod: 'gist_import',
        inputSource: gistUrl,
        filename: selectedFile.filename,
        timeoutMs: req.body.timeout ? Math.min(parseInt(req.body.timeout), 30000) : undefined,
        memoryLimitMb: req.body.memoryLimit ? Math.min(parseInt(req.body.memoryLimit), 256) : undefined,
      },
      (event, data) => {
        broadcastEvent(event, data);
      }
    );

    res.json({
      ...result,
      gistInfo: {
        id: gist.id,
        description: gist.description,
        files: Object.keys(files),
        selectedFile: selectedFile.filename,
        owner: gist.owner?.login,
      }
    });
  } catch (err) {
    console.error('Gist execute error:', err);
    res.status(500).json({ error: 'Execution failed: ' + err.message });
  }
});

// ============================================================
// POST /api/analyze — Static analysis only (no execution)
// ============================================================
router.post('/analyze', (req, res) => {
  try {
    const { code, language } = req.body;

    if (!code || !language) {
      return res.status(400).json({ error: 'Code and language are required' });
    }

    const result = analyzeCode(code.trim(), language.toLowerCase());
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Analysis failed: ' + err.message });
  }
});

// ============================================================
// GET /api/executions — List execution history
// ============================================================
router.get('/executions', (req, res) => {
  try {
    const { limit, offset, language, verdict, status, search, sortBy, sortOrder } = req.query;
    const result = listExecutions({
      limit: parseInt(limit) || 50,
      offset: parseInt(offset) || 0,
      language,
      verdict,
      status,
      search,
      sortBy,
      sortOrder,
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Failed to list executions: ' + err.message });
  }
});

// ============================================================
// GET /api/executions/:id — Get execution details
// ============================================================
router.get('/executions/:id', (req, res) => {
  try {
    const execution = getExecution(req.params.id);
    if (!execution) {
      return res.status(404).json({ error: 'Execution not found' });
    }
    res.json(execution);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get execution: ' + err.message });
  }
});

// ============================================================
// DELETE /api/executions/:id — Delete execution
// ============================================================
router.delete('/executions/:id', (req, res) => {
  try {
    const execution = getExecution(req.params.id);
    if (!execution) {
      return res.status(404).json({ error: 'Execution not found' });
    }
    deleteExecution(req.params.id);
    res.json({ message: 'Execution deleted', id: req.params.id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete execution: ' + err.message });
  }
});

// ============================================================
// GET /api/stats — Dashboard statistics
// ============================================================
router.get('/stats', (req, res) => {
  try {
    const stats = getStats();
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get stats: ' + err.message });
  }
});

export default router;
