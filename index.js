const express = require('express');
const app = express();
app.use(express.json());
app.post('/parse/pdf', (req, res) => {
  const { url } = req.body;
  // hier deine Logik… (z. B. pdf-parse)
  res.json({ text: "Hier der Beispieltext" });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));

