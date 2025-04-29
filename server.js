const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const VT_API_KEY = process.env.VT_API_KEY;

const corsOptions = {
  origin: 'https://shreyansh-123.github.io',  // your GitHub Pages domain
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

app.get('/virustotal', async (req, res) => {
  const query = req.query.query;
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/search?query=${query}`, {
      headers: { 'x-apikey': VT_API_KEY }
    });
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch from VirusTotal', details: err.message });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
