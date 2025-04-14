const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const PORT = 8080;

// MIME type mapping
const MIME_TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".wasm": "application/wasm",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
};

// Create HTTP server
const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);

  // Set COOP and COEP headers for SharedArrayBuffer support
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  // Parse URL
  const parsedUrl = url.parse(req.url);
  let requestPath = parsedUrl.pathname;

  // Ignore favicon requests
  if (requestPath === "/favicon.ico") {
    res.writeHead(204); // No content
    res.end();
    return;
  }

  // Handle root path
  let filePath = "." + requestPath;
  if (filePath === "./") {
    filePath = "./index.html";
  }

  // Handle pkg files (including snippets)
  if (requestPath.startsWith("/pkg/")) {
    // Map to the parent directory structure
    filePath = ".." + requestPath;
    console.log(`Mapped pkg path: ${filePath}`);
  }

  // Determine content type based on file extension
  const extname = path.extname(filePath);
  const contentType = MIME_TYPES[extname] || "application/octet-stream";

  // ❗ Block directory reads
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    console.error(`Attempted directory read: ${filePath}`);
    res.writeHead(403);
    res.end("Forbidden: Cannot read directory directly");
    return;
  }

  // Read and serve the file
  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code === "ENOENT") {
        console.error(`File not found: ${filePath}`);
        res.writeHead(404);
        res.end(`File not found: ${requestPath}`);
      } else {
        console.error(`Server error (${error.code}): ${filePath}`);
        res.writeHead(500);
        res.end(`Server Error: ${error.code}`);
      }
    } else {
      res.writeHead(200, { "Content-Type": contentType });
      res.end(content, "utf-8");
      console.log(`Served: ${filePath} (${contentType})`);
    }
  });
});

// Start the server
server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
