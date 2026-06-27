const { createProxyMiddleware } = require('http-proxy-middleware');

const TARGET = 'http://127.0.0.1:8000';

module.exports = function (app) {
  app.use('/api', createProxyMiddleware({ target: TARGET, changeOrigin: true, ws: false }));
  app.use('/health', createProxyMiddleware({ target: TARGET, changeOrigin: true }));
  app.use('/ready', createProxyMiddleware({ target: TARGET, changeOrigin: true }));
  app.use('/system', createProxyMiddleware({ target: TARGET, changeOrigin: true })); // /system/status
};