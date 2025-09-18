// api/index.js
// Vercel will invoke whatever we export here for every request.
// Our server.js exports the Express `app` when running on Vercel.
const app = require('../server');
module.exports = app;
