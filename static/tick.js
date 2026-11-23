// Taktgeber. Er läuft in einem eigenen Arbeiter des Browsers, weil Browser die Zeitgeber
// einer Seite im Hintergrund stark bremsen. So bleibt der feste Takt derselbe, ob das
// Fenster vorne liegt oder nicht. Diese Datei kennt keine Inhalte: Sie meldet nur
// "jetzt" für die Nummer, die ihr mit einer Wartezeit geschickt wurde.
"use strict";
self.onmessage = function (e) {
  var d = e.data || {};
  setTimeout(function () { self.postMessage(d.id); }, Math.max(0, Number(d.ms) || 0));
};
