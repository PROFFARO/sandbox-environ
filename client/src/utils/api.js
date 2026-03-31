const API_BASE = 'http://localhost:3001/api';
const WS_BASE = 'ws://localhost:3001/ws';

export async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const config = {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  };

  if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
    config.body = JSON.stringify(config.body);
  }

  if (config.body instanceof FormData) {
    delete config.headers['Content-Type'];
  }

  const res = await fetch(url, config);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

export function executeCode(code, language, options = {}) {
  return apiRequest('/execute', {
    method: 'POST',
    body: { code, language, ...options },
  });
}

export function executeFile(formData) {
  return apiRequest('/execute/upload', {
    method: 'POST',
    body: formData,
    headers: {},
  });
}

export function executeFromUrl(url, language, options = {}) {
  return apiRequest('/execute/url', {
    method: 'POST',
    body: { url, language, ...options },
  });
}

export function executeFromGist(gistUrl, language, options = {}) {
  return apiRequest('/execute/gist', {
    method: 'POST',
    body: { gistUrl, language, ...options },
  });
}

export function analyzeOnly(code, language) {
  return apiRequest('/analyze', {
    method: 'POST',
    body: { code, language },
  });
}

export function getExecutions(params = {}) {
  // Strip undefined/null/empty values to prevent "undefined" string serialization
  const filteredParams = Object.fromEntries(
    Object.entries(params).filter(([_, v]) => v != null && v !== '')
  );
  const qs = new URLSearchParams(filteredParams).toString();
  return apiRequest(`/executions?${qs}`);
}

export function getExecution(id) {
  return apiRequest(`/executions/${id}`);
}

export function deleteExecution(id) {
  return apiRequest(`/executions/${id}`, { method: 'DELETE' });
}

export function getStats() {
  return apiRequest('/stats');
}

export function getPolicies() {
  return apiRequest('/policies');
}

export function getPolicy(language) {
  return apiRequest(`/policies/${language}`);
}

// WebSocket connection
export function createWebSocket(onMessage) {
  const ws = new WebSocket(WS_BASE);

  ws.onopen = () => {
    // Subscribe to all events
    ws.send(JSON.stringify({ type: 'subscribe', executionId: '*' }));
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (e) { /* ignore */ }
  };

  ws.onerror = () => {};
  ws.onclose = () => {
    // Auto-reconnect after 3 seconds
    setTimeout(() => createWebSocket(onMessage), 3000);
  };

  return ws;
}

export { API_BASE, WS_BASE };
