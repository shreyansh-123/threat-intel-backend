const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();  // Define the express app
const PORT = process.env.PORT || 3000;

// Set your VirusTotal API Key (from the .env file)
const VT_API_KEY = process.env.VT_API_KEY;

// CORS configuration to allow access from your frontend
const corsOptions = {
  origin: 'https://shreyansh-123.github.io',  // Your GitHub Pages domain
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));  // Use CORS with the specified options

// Endpoint to handle VirusTotal lookups for multiple IPs
app.get('/virustotal', async (req, res) => {
  // Split the IPs from the query, trim them and create a comma-separated list
  const queries = req.query.query.split(',').map(q => q.trim());
  const results = [];

  // Loop through each IP and query VirusTotal API
  for (const ip of queries) {
    try {
      // Send request to VirusTotal API to get the data for the IP
      const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: { 'x-apikey': VT_API_KEY }
      });

      const data = response.data.data;
      const attributes = data.attributes;
      const maliciousCount = attributes.last_analysis_stats.malicious;
      const totalVendors = 94;  // Total vendors in VirusTotal
      const isp = attributes.as_owner || "Unknown ISP";
      const country = attributes.country || "Unknown Country";

      // Check if the IP is clean or malicious and format the response
      if (maliciousCount === 0) {
        results.push(`✅ ${ip}: This IP address is found clean and belongs to ${isp} and country is ${country}.`);
      } else {
        results.push(`❌ ${ip}: This IP address is found malicious from ${maliciousCount}/${totalVendors} vendors and belongs to ${isp} and country is ${country}.`);
      }

    } catch (err) {
      // If there is an error fetching data from VirusTotal, display the error
      results.push(`⚠️ ${ip}: Error fetching data (${err.response?.data?.error?.message || err.message})`);
    }
  }

  // Send the response back as a JSON object
  res.json({ results });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

