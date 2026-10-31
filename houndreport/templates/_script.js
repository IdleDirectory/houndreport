(function () {
  "use strict";
  var root = document.documentElement;
  var THEME_KEY = "houndreport-theme";

  // Theme: follow the OS unless the viewer picked one; remember it when storage is available.
  try {
    var saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  } catch (e) { /* storage unavailable */ }
  var themeBtn = document.getElementById("theme-toggle");
  if (themeBtn) themeBtn.addEventListener("click", function () {
    var current = root.getAttribute("data-theme") ||
      (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    var next = current === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* ignore */ }
  });
  var printBtn = document.getElementById("print-btn");
  if (printBtn) printBtn.addEventListener("click", function () { window.print(); });

  // Sortable tables. A table with class "grouped" sorts its <tbody> groups by their first row.
  function cellValue(row, idx) {
    var cell = row && row.cells[idx];
    if (!cell) return "";
    var v = cell.getAttribute("data-value");
    return v !== null ? v : cell.textContent.trim();
  }
  function compare(a, b, numeric) {
    if (numeric) return (parseFloat(a) || 0) - (parseFloat(b) || 0);
    return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
  }
  Array.prototype.forEach.call(document.querySelectorAll("table.sortable"), function (table) {
    if (!table.tHead) return;
    var headers = table.tHead.rows[0].cells;
    Array.prototype.forEach.call(headers, function (th, idx) {
      if (th.hasAttribute("data-nosort")) return;
      th.tabIndex = 0;
      function sort() {
        var dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
        Array.prototype.forEach.call(headers, function (h) { h.removeAttribute("aria-sort"); });
        th.setAttribute("aria-sort", dir);
        var numeric = th.getAttribute("data-type") === "num";
        var grouped = table.classList.contains("grouped");
        var parent = grouped ? table : table.tBodies[0];
        var items = Array.prototype.slice.call(grouped ? table.tBodies : table.tBodies[0].rows);
        items.sort(function (a, b) {
          var r = compare(cellValue(grouped ? a.rows[0] : a, idx), cellValue(grouped ? b.rows[0] : b, idx), numeric);
          return dir === "ascending" ? r : -r;
        });
        items.forEach(function (item) { parent.appendChild(item); });
      }
      th.addEventListener("click", sort);
      th.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); }
      });
    });
  });

  // Finding rows expand to show details.
  function setExpanded(group, open) {
    var btn = group.querySelector(".expander");
    var detail = group.querySelector(".detail-row");
    if (!btn || !detail) return;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    detail.hidden = !open;
  }
  Array.prototype.forEach.call(document.querySelectorAll("tbody.finding"), function (group) {
    group.rows[0].addEventListener("click", function (e) {
      if (e.target.closest("a")) return;
      setExpanded(group, group.querySelector(".expander").getAttribute("aria-expanded") !== "true");
    });
  });
  function expandAll(open) {
    Array.prototype.forEach.call(document.querySelectorAll("tbody.finding"), function (g) { setExpanded(g, open); });
  }
  var ea = document.getElementById("expand-all"), ca = document.getElementById("collapse-all");
  if (ea) ea.addEventListener("click", function () { expandAll(true); });
  if (ca) ca.addEventListener("click", function () { expandAll(false); });
  if (location.hash && location.hash.indexOf("#f-") === 0) {
    var target = document.getElementById(location.hash.slice(1));
    if (target) setExpanded(target, true);
  }
  Array.prototype.forEach.call(document.querySelectorAll('a[href^="#f-"]'), function (a) {
    a.addEventListener("click", function () {
      var t = document.getElementById(a.getAttribute("href").slice(1));
      if (t) setExpanded(t, true);
    });
  });

  // Findings filter: free text + severity chips.
  var search = document.getElementById("finding-search");
  var sevBoxes = document.querySelectorAll(".sev-filter");
  var counter = document.getElementById("finding-count");
  function applyFindingFilter() {
    var q = search ? search.value.trim().toLowerCase() : "";
    var allowed = {};
    Array.prototype.forEach.call(sevBoxes, function (b) { allowed[b.value] = b.checked; });
    var shown = 0, groups = document.querySelectorAll("tbody.finding");
    Array.prototype.forEach.call(groups, function (g) {
      var ok = allowed[g.getAttribute("data-severity")] !== false &&
        (!q || g.getAttribute("data-search").indexOf(q) !== -1);
      g.hidden = !ok;
      if (ok) shown++;
    });
    if (counter) counter.textContent = shown + " of " + groups.length + " findings shown";
  }
  if (search) search.addEventListener("input", applyFindingFilter);
  Array.prototype.forEach.call(sevBoxes, function (b) { b.addEventListener("change", applyFindingFilter); });
  applyFindingFilter();

  // Per-table row filters.
  Array.prototype.forEach.call(document.querySelectorAll("input.table-filter"), function (input) {
    var table = document.getElementById(input.getAttribute("data-target"));
    if (!table) return;
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
        row.hidden = q && row.textContent.toLowerCase().indexOf(q) === -1;
      });
    });
  });
})();
