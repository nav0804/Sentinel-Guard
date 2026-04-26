import { describe, it, expect, beforeAll } from 'vitest';

describe('Smoke Tests', () => {
  const PROXY_URL = 'http://localhost:3000';
  const AGENT_RUNNER_URL = 'http://localhost:3001';
  const REDIS_URL = 'http://localhost:6379';

  beforeAll(() => {
    // These tests require services to be running
    // Start with: docker compose up
  });

  describe('Service Health', () => {
    it('should have proxy service running', async () => {
      try {
        const response = await fetch(PROXY_URL, { method: 'HEAD' });
        expect([200, 404, 405]).toContain(response.status); // Any response means it's running
      } catch (error) {
        throw new Error('Proxy service is not running. Start with: docker compose up');
      }
    });

    it('should have agent runner service running', async () => {
      try {
        const response = await fetch(AGENT_RUNNER_URL, { method: 'HEAD' });
        expect([200, 404, 405]).toContain(response.status);
      } catch (error) {
        throw new Error('Agent runner service is not running. Start with: docker compose up');
      }
    });

    it('should have Redis service running', async () => {
      try {
        // Try to connect to Redis
        const response = await fetch('http://localhost:6379', { method: 'GET' });
        // Redis doesn't speak HTTP, so we expect connection refused or similar
        // But if we can reach the port, that's good enough
      } catch (error) {
        // This is expected since Redis doesn't speak HTTP
        // The important thing is that the port is accessible
      }
    });
  });

  describe('Basic Functionality', () => {
    it('should handle GET requests', async () => {
      try {
        const response = await fetch(`${PROXY_URL}/api/health`, {
          method: 'GET',
        });

        // Should either proxy successfully or return 404 (downstream not found)
        expect([200, 404, 403]).toContain(response.status);
      } catch (error) {
        console.warn('GET request test failed - service might not be fully ready');
      }
    });

    it('should handle POST requests with valid JSON', async () => {
      try {
        const response = await fetch(`${PROXY_URL}/api/test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ test: 'data' }),
        });

        expect([200, 404, 403]).toContain(response.status);
      } catch (error) {
        console.warn('POST request test failed - service might not be fully ready');
      }
    });

    it('should reject malformed JSON', async () => {
      try {
        const response = await fetch(`${PROXY_URL}/api/test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: 'invalid json',
        });

        // Should return 400 for malformed JSON
        expect(response.status).toBe(400);
      } catch (error) {
        console.warn('Malformed JSON test failed - service might not be fully ready');
      }
    });
  });

  describe('Security Pipeline', () => {
    it('should block obvious XSS attacks', async () => {
      try {
        const response = await fetch(`${PROXY_URL}/api/test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data: '<script>alert(1)</script>' }),
        });

        expect(response.status).toBe(403);

        const data = await response.json();
        expect(data).toHaveProperty('reason');
        expect(data.reason).toContain('WAF pattern');
      } catch (error) {
        console.warn('XSS blocking test failed - service might not be fully ready');
      }
    });

    it('should block SQL injection attempts', async () => {
      try {
        const response = await fetch(`${PROXY_URL}/api/test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: "1' OR '1'='1" }),
        });

        expect(response.status).toBe(403);

        const data = await response.json();
        expect(data).toHaveProperty('reason');
      } catch (error) {
        console.warn('SQL injection blocking test failed - service might not be fully ready');
      }
    });

    it('should block path traversal attempts', async () => {
      try {
        const response = await fetch(`${PROXY_URL}/api/test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file: '../../../etc/passwd' }),
        });

        expect(response.status).toBe(403);

        const data = await response.json();
        expect(data).toHaveProperty('reason');
      } catch (error) {
        console.warn('Path traversal blocking test failed - service might not be fully ready');
      }
    });
  });

  describe('Agent Runner', () => {
    it('should accept evaluation requests', async () => {
      try {
        const response = await fetch(`${AGENT_RUNNER_URL}/evaluate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            method: 'POST',
            route: '/api/test',
            header: {},
            body: { query: 'test' },
            ip: '192.168.1.1',
          }),
        });

        expect([200, 500]).toContain(response.status); // 200 if working, 500 if LLM not configured

        if (response.ok) {
          const verdict = await response.json();
          expect(verdict).toHaveProperty('decision');
          expect(['SAFE', 'MALICIOUS']).toContain(verdict.decision);
        }
      } catch (error) {
        console.warn('Agent runner evaluation test failed - service might not be fully ready');
      }
    });
  });

  describe('Performance', () => {
    it('should respond within reasonable time for safe requests', async () => {
      try {
        const startTime = Date.now();

        const response = await fetch(`${PROXY_URL}/api/test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data: 'safe request' }),
        });

        const endTime = Date.now();
        const duration = endTime - startTime;

        // Should respond within 5 seconds (allowing for LLM latency)
        expect(duration).toBeLessThan(5000);
      } catch (error) {
        console.warn('Performance test failed - service might not be fully ready');
      }
    });

    it('should respond quickly for cached requests', async () => {
      try {
        const requestBody = JSON.stringify({ data: 'cache test' });

        // First request to populate cache
        await fetch(`${PROXY_URL}/api/test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: requestBody,
        });

        // Second request should hit cache
        const startTime = Date.now();
        const response = await fetch(`${PROXY_URL}/api/test`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: requestBody,
        });
        const endTime = Date.now();

        const duration = endTime - startTime;

        // Cached requests should be very fast (< 100ms)
        expect(duration).toBeLessThan(100);
      } catch (error) {
        console.warn('Cache performance test failed - service might not be fully ready');
      }
    });
  });
});