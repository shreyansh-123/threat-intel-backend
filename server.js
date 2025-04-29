app.get('/virustotal', async (req, res) => {
  const queries = req.query.query.split(',').map(q => q.trim());
  const results = [];

  for (const ip of queries) {
    try {
      const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: { 'x-apikey': VT_API_KEY }
      });

      const data = response.data.data;
      const attributes = data.attributes;
      const maliciousCount = attributes.last_analysis_stats.malicious;
      const totalVendors = 94;
      const isp = attributes.as_owner || "Unknown ISP";
      const country = attributes.country || "Unknown Country";

      if (maliciousCount === 0) {
        results.push(`✅ ${ip}: This IP address is found clean and belongs to ${isp} and country is ${country}.`);
      } else {
        results.push(`❌ ${ip}: This IP address is found malicious from ${maliciousCount}/${totalVendors} vendors and belongs to ${isp} and country is ${country}.`);
      }

    } catch (err) {
      results.push(`⚠️ ${ip}: Error fetching data (${err.response?.data?.error?.message || err.message})`);
    }
  }

  res.json({ results });
});
