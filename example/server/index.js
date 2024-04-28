import http from "node:http";

const host = "localhost";
const port = 3000;

function requestHandler(req, res) {
  console.log(req.method, req.url);
  res.setHeader("Content-Type", "application/json");
  res.setHeader("X-Public-Key", "abcedefghijklmn");
  res.writeHead(200);
  res.end(`{ "message": "hello friends" }`);
}

const server = http.createServer(requestHandler);
server.listen(port, host, () => {
  console.log(`Server is running on http://${host}:${port}`);
});
