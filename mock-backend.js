// mock-backend.js
import http from 'http';

const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', chunk => { body += chunk.toString(); });
  req.on('end', () => {
    console.log(`[Mock Backend] Received ${req.method} ${req.url}`);
    console.log(`[Mock Backend] Body:`, body);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      message: "Success! Your request passed the WAF and reached the backend safely.",
      received: body ? JSON.parse(body) : null
    }));
  });
});

server.listen(4000, () => {
  console.log('🟢 Mock Backend listening on http://localhost:4000');
});