const form = document.querySelector("#builder");
const output = document.querySelector("#output");
const copy = document.querySelector("#copy");

const values = (selector) => document.querySelector(selector).value
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

function manifest() {
  const domains = values("#domains");
  return {
    version: "kyntral.capability.v1",
    id: document.querySelector("#capabilityId").value.trim(),
    moduleVersion: document.querySelector("#moduleVersion").value.trim(),
    publisher: {
      id: document.querySelector("#publisherId").value.trim(),
      name: document.querySelector("#publisherName").value.trim()
    },
    risk: document.querySelector("#risk").value,
    execution: {
      location: document.querySelector("#location").value,
      backgroundAllowed: document.querySelector("#background").checked
    },
    deviceData: values("#deviceData"),
    network: domains.length
      ? { access: "allowlist", domains }
      : { access: "none" },
    sideEffects: values("#effects"),
    destinations: values("#destinations"),
    minimumKyntralVersion: "0.1.0"
  };
}

function render() {
  output.textContent = JSON.stringify(manifest(), null, 2);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  render();
});

copy.addEventListener("click", async () => {
  await navigator.clipboard.writeText(output.textContent);
  copy.textContent = "Copied";
  setTimeout(() => { copy.textContent = "Copy JSON"; }, 1200);
});

render();
