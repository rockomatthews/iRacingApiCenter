// server.js
require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 10000;  // Render.com uses PORT environment variable

// Middleware
app.use(express.json());
app.use(cors());

// Basic root route
app.get('/', (req, res) => {
  res.json({ 
    message: 'iRacing API Gateway Service', 
    status: 'active',
    timestamp: new Date().toISOString()
  });
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Global variables for auth
let cookieJar = null;
let lastAuthTime = null;
const AUTH_EXPIRY = 60 * 60 * 1000; // 1 hour

// Debug logging function
function debugLog(message, data = '') {
  console.log(`[${new Date().toISOString()}] ${message}`, data);
}

// Helper function to encode password according to iRacing specs
function encodePassword(password, email) {
  const hash = crypto.createHash('sha256')
    .update(password + email.toLowerCase())
    .digest();
  return hash.toString('base64');
}

// Auth middleware
async function authenticateIRacing(req, res, next) {
  try {
    const currentTime = Date.now();
    if (!cookieJar || !lastAuthTime || (currentTime - lastAuthTime) > AUTH_EXPIRY) {
      debugLog('Attempting authentication with iRacing...');
      
      const email = process.env.IRACING_EMAIL;
      const password = process.env.IRACING_PASSWORD;
      
      if (!email || !password) {
        throw new Error('iRacing credentials not configured in environment variables');
      }

      const encodedPassword = encodePassword(password, email);
      
      const response = await fetch('https://members-ng.iracing.com/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password: encodedPassword
        })
      });

      debugLog('Auth response status:', response.status);
      
      if (!response.ok) {
        const errorText = await response.text();
        debugLog('Auth error response:', errorText);
        throw new Error(`Authentication failed with status ${response.status}: ${errorText}`);
      }

      // Store the complete Set-Cookie header
      const setCookieHeaders = response.headers.raw()['set-cookie'];
      if (!setCookieHeaders || setCookieHeaders.length === 0) {
        throw new Error('No cookies received from authentication');
      }

      // Store the complete cookie string
      cookieJar = setCookieHeaders.join('; ');
      lastAuthTime = currentTime;
      
      debugLog('Authentication successful, stored cookies');
    }
    next();
  } catch (error) {
    debugLog('Authentication error:', error.message);
    res.status(500).json({ error: 'Authentication failed', details: error.message });
  }
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    service: 'iRacing API Gateway',
    timestamp: new Date().toISOString(),
    authenticated: !!cookieJar,
    lastAuthTime: lastAuthTime ? new Date(lastAuthTime).toISOString() : null,
    environment: process.env.NODE_ENV || 'development'
  });
});

// Test auth endpoint
app.get('/api/test-auth', authenticateIRacing, (req, res) => {
  res.json({ 
    status: 'Authentication successful',
    lastAuthTime: lastAuthTime ? new Date(lastAuthTime).toISOString() : null,
    hasCookies: !!cookieJar,
    cookieJarPreview: cookieJar ? cookieJar.substring(0, 100) + '...' : null
  });
});

// RealNameSearch endpoint
app.get('/api/search/realname', authenticateIRacing, async (req, res) => {
  try {
    const searchTerm = req.query.name;
    if (!searchTerm) {
      return res.status(400).json({ error: 'Name parameter is required' });
    }

    debugLog(`Searching for name: ${searchTerm}`);

    const searchUrl = `https://members-ng.iracing.com/data/lookup/drivers?search_term=${encodeURIComponent(searchTerm)}`;
    debugLog('Making search request to:', searchUrl);

    const searchResponse = await fetch(searchUrl, {
      method: 'GET',
      headers: {
        'Cookie': cookieJar
      }
    });

    if (!searchResponse.ok) {
      const errorText = await searchResponse.text();
      debugLog('Search error response:', errorText);
      throw new Error(`iRacing API request failed with status ${searchResponse.status}: ${errorText}`);
    }

    const initialData = await searchResponse.json();
    debugLog('Received initial response:', initialData);

    // Handle the link response pattern
    if (initialData.link) {
      debugLog('Following data link:', initialData.link);
      const dataResponse = await fetch(initialData.link);
      
      if (!dataResponse.ok) {
        const errorText = await dataResponse.text();
        debugLog('Data link error response:', errorText);
        throw new Error(`Failed to fetch driver data: ${errorText}`);
      }

      const finalData = await dataResponse.json();
      debugLog('Received final data');
      return res.json({
        success: true,
        data: finalData,
        timestamp: new Date().toISOString()
      });
    }

    res.json({
      success: true,
      data: initialData,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    debugLog('Search error:', error.message);
    res.status(500).json({ 
      error: 'Failed to search for name', 
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Error handling for undefined routes
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested endpoint does not exist',
    timestamp: new Date().toISOString()
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' ? 'An unexpected error occurred' : err.message,
    timestamp: new Date().toISOString()
  });
});

// Start the server
app.listen(port, () => {
  debugLog(`iRacing API Gateway running on port ${port}`);
  debugLog(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Handle process termination
process.on('SIGTERM', () => {
  debugLog('SIGTERM received. Performing graceful shutdown...');
  process.exit(0);
});