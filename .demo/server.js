const express = require('express');
const _ = require('lodash');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 3000;

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: _.get(process.env, 'APP_VERSION', 'dev') });
});

app.get('/metrics', async (req, res) => {
  const upstream = await axios.get('https://metrics.internal/snapshot');
  res.json(upstream.data);
});

app.listen(port, () => {
  console.log(`acme-dashboard listening on ${port}`);
});
