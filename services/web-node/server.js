import express from "express";

const app = express();
const port = process.env.PORT || 3000;
const apiBaseUrl = process.env.API_BASE_URL || "http://localhost:8000";

app.use(express.json());
app.use(express.static("public"));

app.get("/api/options", async (_req, res) => {
  const response = await fetch(`${apiBaseUrl}/options`);
  res.status(response.status).json(await response.json());
});

app.post("/api/votes", async (req, res) => {
  const response = await fetch(`${apiBaseUrl}/votes`, {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify(req.body)
  });
  res.status(response.status).json(await response.json());
});

app.get("/api/results", async (_req, res) => {
  const response = await fetch(`${apiBaseUrl}/results`);
  res.status(response.status).json(await response.json());
});

app.listen(port, () => {
  console.log(`Season voting web app listening on ${port}`);
});
