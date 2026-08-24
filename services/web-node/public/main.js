const choices = document.querySelector("#choices");
const results = document.querySelector("#results");
const message = document.querySelector("#message");

async function loadOptions() {
  const response = await fetch("/api/options");
  const data = await response.json();
  choices.innerHTML = "";
  data.options.forEach((season) => {
    const button = document.createElement("button");
    button.textContent = season[0].toUpperCase() + season.slice(1);
    button.addEventListener("click", () => submitVote(season));
    choices.appendChild(button);
  });
}

async function submitVote(season) {
  const response = await fetch("/api/votes", {
    method: "POST",
    headers: {"content-type": "application/json"},
    body: JSON.stringify({season})
  });
  const data = await response.json();
  message.textContent = response.ok ? `Vote recorded for ${data.season}.` : data.error;
  await loadResults();
}

async function loadResults() {
  const response = await fetch("/api/results");
  const data = await response.json();
  results.innerHTML = "";
  Object.entries(data.results).forEach(([season, count]) => {
    const row = document.createElement("div");
    row.className = "result-row";
    row.innerHTML = `<span>${season}</span><strong>${count}</strong>`;
    results.appendChild(row);
  });
}

loadOptions();
loadResults();
setInterval(loadResults, 5000);
