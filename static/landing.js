// mesh Info-Seite "über Tor": ausgelagert, damit die Seite ohne Inline-Script auskommt.
document.getElementById("btn-copy").addEventListener("click", () => {
  const txt = document.getElementById("onion-addr").textContent;
  navigator.clipboard.writeText(txt).then(() => {
    const b = document.getElementById("btn-copy");
    const orig = b.textContent;
    b.textContent = "Kopiert!";
    setTimeout(() => b.textContent = orig, 1500);
  });
});
