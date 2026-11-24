// Kerala backwater scene for the social and README cards: sunset, palms, a lit kettuvallam and its reflection.
// Usage: <div id="kscene"></div><script src="kerala-scene.js"></script> (add ../ for readme/ cards). Fixed seed, so every render matches.
(function () {
  var host = document.getElementById('kscene');
  if (!host) return;
  var W = host.clientWidth || 1600, H = parseInt(host.dataset.h || '150', 10), HZ = parseInt(host.dataset.hz || '84', 10), SR = parseFloat(host.dataset.sr || '1'); // band height, horizon, scale
  var NS = 'http://www.w3.org/2000/svg', sd = 77;
  function r() { sd = (sd * 1103515245 + 12345) & 0x7fffffff; return sd / 0x7fffffff; }
  var svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H); svg.setAttribute('width', W); svg.setAttribute('height', H);
  svg.style.display = 'block'; svg.style.position = 'absolute'; svg.style.left = '0'; svg.style.bottom = '0';
  function el(n, a, p) { var e = document.createElementNS(NS, n); for (var k in a) e.setAttribute(k, a[k]); (p || svg).appendChild(e); return e; }
  var defs = el('defs', {});
  defs.innerHTML =
    '<radialGradient id="sg"><stop offset="0" stop-color="#ffb347" stop-opacity=".85"/><stop offset=".35" stop-color="#ff6a3d" stop-opacity=".38"/><stop offset=".7" stop-color="#8a2b5c" stop-opacity=".14"/><stop offset="1" stop-color="#000" stop-opacity="0"/></radialGradient>' +
    '<linearGradient id="sn" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffe08a"/><stop offset=".6" stop-color="#ff9a3c"/><stop offset="1" stop-color="#ff4d4d"/></linearGradient>' +
    '<linearGradient id="wt" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#6b3320" stop-opacity=".8"/><stop offset=".25" stop-color="#1b1a26" stop-opacity=".9"/><stop offset="1" stop-color="#000"/></linearGradient>' +
    '<radialGradient id="lp"><stop offset="0" stop-color="#fff2b8"/><stop offset=".4" stop-color="#ffc857" stop-opacity=".7"/><stop offset="1" stop-color="#ffb347" stop-opacity="0"/></radialGradient>' +
    '<clipPath id="ab"><rect x="0" y="0" width="' + W + '" height="' + HZ + '"/></clipPath>';
  var SX = W * parseFloat(host.dataset.sun || '0.16'); // sun
  el('rect', { x: 0, y: 0, width: W, height: H, fill: '#000' });
  el('ellipse', { cx: SX, cy: HZ, rx: W * 0.36, ry: 120 * SR, fill: 'url(#sg)' });
  var sg = el('g', { 'clip-path': 'url(#ab)' }); el('circle', { cx: SX, cy: HZ, r: 44 * SR, fill: 'url(#sn)' }, sg);
  for (var s = 0; s < W / 26; s++) el('circle', { cx: (r() * W).toFixed(0), cy: (r() * HZ * 0.8).toFixed(0), r: (0.5 + r() * 1.1).toFixed(1), fill: '#fff', opacity: (0.2 + r() * 0.5).toFixed(2) });
  var d = 'M0,' + HZ + ' L0,' + (HZ - 14); for (var x = 0; x <= W; x += 90) d += ' Q' + (x + 45) + ',' + (HZ - 26 - r() * 6) + ' ' + (x + 90) + ',' + (HZ - 12 - r() * 6);
  el('path', { d: d + ' L' + W + ',' + HZ + ' Z', fill: '#050b12' });
  function palm(g, x, y, h, lean, sc, fill, rim) {
    var tx = x + lean, ty = y - h;
    el('path', { d: 'M' + x + ',' + y + ' C' + (x + lean * .15) + ',' + (y - h * .5) + ' ' + (x + lean * .7) + ',' + (y - h * .8) + ' ' + tx + ',' + ty, fill: 'none', stroke: fill, 'stroke-width': (7 * sc).toFixed(1), 'stroke-linecap': 'round' }, g);
    for (var i = 0; i < 13; i++) {
      var a = (-172 + i * (164 / 12) + (r() - .5) * 8) * Math.PI / 180, L = (40 + r() * 26) * sc, ca = Math.cos(a), sa = Math.sin(a);
      var ex = tx + ca * L, ey = ty + 6 * sc + Math.abs(ca) * 30 * sc + sa * 8 * sc, cx = tx + ca * L * .55, cy = ty - (14 + 22 * Math.abs(sa)) * sc;
      el('path', { d: 'M' + tx + ',' + ty + ' Q' + cx.toFixed(1) + ',' + cy.toFixed(1) + ' ' + ex.toFixed(1) + ',' + ey.toFixed(1) + ' Q' + (cx + 2 * sc).toFixed(1) + ',' + (cy + 8 * sc).toFixed(1) + ' ' + tx + ',' + ty + ' Z', fill: fill, stroke: rim, 'stroke-width': '.8', 'stroke-opacity': '.55' }, g);
    }
  }
  var far = el('g', {}); for (var fx = 140; fx < W; fx += 210 + r() * 90) palm(far, fx, HZ - 4, (34 + r() * 8) * SR, (r() - .5) * 12, .5 * SR, '#07111b', '#ff8a3c');
  el('rect', { x: 0, y: HZ, width: W, height: H - HZ, fill: 'url(#wt)' });
  var sh = el('g', { stroke: '#ffd27a', 'stroke-linecap': 'round' });
  for (var k = 0; k < 14; k++) { var w = 120 - k * 6 + r() * 20, x0 = SX - w / 2 + (r() - .5) * 18, y = HZ + 4 + k * 4.4; el('line', { x1: x0, y1: y, x2: x0 + w, y2: y, 'stroke-width': (1.4 + r() * 1.6).toFixed(1), 'stroke-opacity': (.75 - k * .04).toFixed(2) }, sh); }
  var BX = W * parseFloat(host.dataset.boat || '0.5'), boat = '<path d="M-120,112 Q0,128 120,112 L108,100 L-108,100 Z" fill="#02050a" stroke="#ff9a3c" stroke-opacity=".55"/><path d="M-96,100 Q-96,64 0,64 Q96,64 96,100 Z" fill="#02050a" stroke="#ff9a3c" stroke-opacity=".6" stroke-width="1.2"/><path d="M-70,100 Q-70,70 -50,66 M-30,100 Q-30,66 -8,64 M18,100 Q18,66 36,65 M58,100 Q58,72 70,68" fill="none" stroke="#ff9a3c" stroke-opacity=".28"/>';
  [-60, -28, 4, 36].forEach(function (lx) { boat += '<rect x="' + lx + '" y="84" width="14" height="9" rx="2" fill="#ffc857"/><circle cx="' + (lx + 7) + '" cy="88" r="16" fill="url(#lp)"/>'; });
  var off = HZ - 122, bg = el('g', { transform: 'translate(' + BX + ',' + off + ') scale(' + (.85 * SR) + ')' }); bg.innerHTML = boat;
  var rg = el('g', { opacity: .26, transform: 'translate(' + BX + ',' + HZ + ') scale(' + (.85 * SR) + ',' + (-.85 * SR) + ') translate(0,-122)' }); rg.innerHTML = boat;
  var pg = el('g', {});
  palm(pg, 30, H, 70, 22, 1.0, '#010409', '#ff9a3c'); palm(pg, 92, H + 4, 52, -10, .8, '#010409', '#ffb35c');
  palm(pg, W - 70, H, 74, -22, 1.05, '#010409', '#ff9a3c'); palm(pg, W - 18, H + 4, 54, 10, .8, '#010409', '#ffb35c');
  var ff = el('g', { fill: '#ffe08a' }); for (var f = 0; f < W / 55; f++) el('circle', { cx: (30 + r() * (W - 60)).toFixed(0), cy: (HZ * 0.5 + r() * (H - HZ * 0.5)).toFixed(0), r: (1 + r() * 1.5).toFixed(1), opacity: (.4 + r() * .5).toFixed(2) }, ff);
  host.appendChild(svg);
})();
