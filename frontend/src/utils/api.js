const rawBackendUrl = (import.meta.env.VITE_BACKEND_URL || import.meta.env.NEXT_PUBLIC_BACKEND_URL || '').trim();
const BACKEND_URL = rawBackendUrl.replace(/\/+$/, '');

/**
 * Helper to get active JWT Auth token from localStorage
 */
export function getAuthToken() {
  return localStorage.getItem('sl_jwt_token') || '';
}

/**
 * Save JWT Auth token to localStorage
 */
export function setAuthToken(token) {
  if (token) {
    localStorage.setItem('sl_jwt_token', token);
  } else {
    localStorage.removeItem('sl_jwt_token');
  }
}

/**
 * Centralized API fetcher
 */
export async function apiFetch(endpoint, options = {}) {
  const token = getAuthToken();
  
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const url = endpoint.startsWith('http') ? endpoint : `${BACKEND_URL}${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers,
  });

  const contentType = response.headers.get('content-type');
  let data = null;
  if (contentType && contentType.includes('application/json')) {
    data = await response.json();
  } else {
    const text = await response.text();
    data = { message: text };
  }

  if (!response.ok) {
    const errorMessage = (data && (data.detail || data.error || data.message)) || `HTTP ${response.status} Error`;
    const err = new Error(errorMessage);
    err.status = response.status;
    err.data = data;
    throw err;
  }

  return data;
}
