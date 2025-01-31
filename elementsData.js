<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PeriodicChiCubo</title>
  <style>
    /* =============================
       GLOBAL STYLING & LAYOUT
       ============================= */
    html, body {
      margin: 0;
      padding: 0;
      width: 100%;
      box-sizing: border-box;
      font-family: "Segoe UI", Tahoma, Arial, sans-serif;
      background: linear-gradient(135deg, #fdfdfd 0%, #e8f0fd 100%);
    }
    body {
      display: flex;
      flex-direction: row;
      gap: 20px;
      margin: 10px;
      padding: 10px;
    }
    .dark-mode {
      background: #333 !important;
      color: #ccc !important;
    }
    .dark-mode a {
      color: #9bd !important;
    }
    .dark-mode button,
    .dark-mode input,
    .dark-mode select,
    .dark-mode textarea {
      background: #555 !important;
      color: #ccc !important;
      border: 1px solid #777 !important;
    }

    /* LEFT COLUMN */
    .left-column {
      flex: 1;
      max-width: 1200px;
      background: #fff;
      border-radius: 6px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.12);
      padding: 15px;
      display: flex;
      flex-direction: column;
    }
    #topBanner {
      text-align: center;
      margin-bottom: 15px;
    }
    #topBanner img {
      max-width: 100%;
      height: auto;
      border-radius: 4px;
    }
    #menuBar {
      margin-bottom: 10px;
      padding: 8px;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-weight: bold;
      font-style: italic;
      background: #f0f7ff;
      color: #333;
      text-align: center;
    }
    #menuBar a {
      margin-right: 10px;
      color: #3498db;
      text-decoration: none;
    }
    #menuBar a:hover {
      text-decoration: underline;
    }
    #darkModeToggle {
      float: right;
      background: #222;
      color: #fff;
      border: none;
      padding: 6px 10px;
      cursor: pointer;
    }
    #darkModeToggle:hover {
      background: #444;
    }
    #userStatusBar {
      margin-bottom: 10px;
      padding: 10px;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-weight: bold;
    }
    #topControls {
      margin-bottom: 15px;
      border: 1px solid #e0e0e0;
      background: #fafafa;
      padding: 10px;
      border-radius: 4px;
    }
    #topControls .row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 10px;
      align-items: center;
    }
    input, select, button {
      margin: 3px 0;
      padding: 6px 8px;
      font-size: 1em;
      border: 1px solid #ccc;
      border-radius: 3px;
    }
    button {
      background: #3498db;
      color: #fff;
      cursor: pointer;
      transition: background 0.2s ease;
      border: none;
    }
    button:hover {
      background: #1f78b4;
    }

    /* PERIODIC TABLE & CHART & SUB-BLOCKS */
    .periodic-container {
      flex: 1;
      display: flex;
      flex-direction: column;
      margin-top: 10px;
      background: #fff;
      border: 1px solid #ddd;
      border-radius: 4px;
      padding: 10px;
    }
    #periodicTable {
      border-collapse: collapse;
      margin-bottom: 10px;
    }
    #periodicTable td {
      width: 60px;
      height: 60px;
      text-align: center;
      vertical-align: middle;
      border: 1px solid #ddd;
      cursor: pointer;
      position: relative;
      transition: background 0.2s ease, outline 0.2s ease;
    }
    #periodicTable td:hover {
      background: #f0f0f0;
    }
    .atomic-number {
      position: absolute;
      top: 2px;
      left: 4px;
      font-size: 10px;
      color: #666;
      pointer-events: none;
    }
    /* Sub-block containers for lanthanides & actinides */
    .sub-block-container {
      margin-top: 8px;
    }
    .sub-block-container table {
      border-collapse: collapse;
      margin-top: 4px;
    }
    .sub-block-container td {
      width: 60px;
      height: 60px;
      text-align: center;
      vertical-align: middle;
      border: 1px solid #ddd;
      cursor: pointer;
      position: relative;
      transition: background 0.2s ease, outline 0.2s ease;
    }
    .sub-block-container td:hover {
      background: #f0f0f0;
    }

    #counters {
      margin-top: 10px;
      font-weight: bold;
    }
    #statusChart {
      width: 200px;
      height: 200px;
      margin: 0 auto;
    }

    /* Outlines => category color, background => status color */
    .cat-outline {
      outline: 3px solid #999;
      outline-offset: -3px;
    }
    .status-pure {
      background-color: #aaffaa !important;
    }
    .status-rep {
      background-color: #ffb3b3 !important;
    }
    .status-alloy {
      background-color: #b3b3ff !important;
    }
    .status-wish {
      background-color: #fffba1 !important;
    }

    /* TOOLTIP */
    #elementTooltip {
      position: absolute;
      background: #fff8d1;
      border: 1px solid #ccc;
      padding: 4px;
      display: none;
      z-index: 9999;
      pointer-events: none;
      font-size: 0.9em;
    }

    /* RIGHT DETAILS PANEL */
    .details-panel {
      width: 400px;
      background: #fff;
      border: 1px solid #ccc;
      padding: 16px;
      border-radius: 6px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.12);
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .edit-mode {
      border: 2px solid #ffbb33 !important;
      background: #fff7e6 !important;
    }
    .view-mode {
      border: 2px solid #999 !important;
      background: #f0f0f0 !important;
    }
    #elementTitle {
      font-weight: bold;
      font-size: 1.1em;
      margin-bottom: 0;
      border-bottom: 1px solid #ddd;
      padding-bottom: 4px;
    }
    textarea {
      width: 100%;
      height: 70px;
      border-radius: 3px;
      border: 1px solid #ccc;
      padding: 6px;
      resize: vertical;
    }
    #previewImg {
      max-width: 100%;
      margin-top: 10px;
      border: 1px solid #ccc;
      display: none;
      border-radius: 4px;
    }

    /* AUTHOR INFO MODAL */
    #authorInfoModal {
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: #fff;
      border: 2px solid #333;
      padding: 20px;
      border-radius: 6px;
      display: none;
      width: 300px;
      max-width: 90%;
      z-index: 9999;
    }
    #authorInfoModal img {
      max-width: 100%;
      margin-top: 10px;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
    #authorInfoClose {
      margin-top: 10px;
      background: #999;
      border: none;
      color: #fff;
      padding: 8px 12px;
      border-radius: 3px;
      cursor: pointer;
    }
    #authorInfoClose:hover {
      background: #666;
    }
  </style>
  <!-- Chart.js for the pie chart -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <!-- LEFT COLUMN -->
  <div class="left-column">
    <div id="topBanner">
      <img src="/static/elementbanner.png" alt="PeriodicChiCubo Banner">
    </div>
    <div id="menuBar">
      <a href="/list">User Directory</a>
      <a href="/profile">Profile Settings</a>
      <a href="/about">About</a>
      <a href="/usage">Usage Guide</a>
      <a href="/media">Media Library</a>
      <button id="darkModeToggle">Dark Mode</button>
    </div>

    <div id="userStatusBar">Not logged in.</div>

    <div id="topControls">
      <div class="row">
        <input type="text" id="usernameInput" placeholder="Username">
        <input type="password" id="passwordInput" placeholder="Password">
        <button id="loginLoadBtn">Login &amp; Load</button>
        <button id="saveBtn">Save</button>
        <button id="logoutBtn" style="display:none;">Logout</button>
      </div>
      <div class="row">
        <input type="text" id="viewUsernameInput" placeholder="View user (public)">
        <button id="viewBtn">View</button>

        <input type="text" id="searchInput" placeholder="Search (symbol/name)">
        <button id="searchBtn">Search</button>

        <button id="viewOwnerInfoBtn">Author Info</button>
      </div>
      <div class="row">
        <label style="display:flex; align-items:center;">
          <input type="checkbox" id="quickStatusCheckbox" style="margin-right:4px;">
          Quick Status
        </label>
        <select id="quickStatusDropdown">
          <option value="">None</option>
          <option value="Pure">Pure</option>
          <option value="Representative">Representative</option>
          <option value="Alloy">Alloy</option>
          <option value="Wish">Wish</option>
        </select>
      </div>
    </div>

    <div class="periodic-container">
      <!-- We'll build the main table skipping lanthanides & actinides. Then show sub-blocks. -->
      <table id="periodicTable"></table>

      <div class="sub-block-container">
        <strong>Lanthanides (La–Lu)</strong>
        <table id="lanthanideTable"></table>
      </div>
      <div class="sub-block-container">
        <strong>Actinides (Ac–Lr)</strong>
        <table id="actinideTable"></table>
      </div>

      <div id="elementTooltip"></div>
      <canvas id="statusChart"></canvas>
    </div>

    <div id="counters">Counters here...</div>
  </div>

  <!-- RIGHT COLUMN: details panel -->
  <div class="details-panel edit-mode" id="detailsPanel">
    <img src="/static/details.png" style="max-width:100%;" alt="Element Details Banner">
    <div id="elementTitle"></div>

    <label>Status:</label>
    <select id="statusSelect">
      <option value="">None</option>
      <option value="Pure">Pure</option>
      <option value="Representative">Representative</option>
      <option value="Alloy">Alloy</option>
      <option value="Wish">Wish</option>
    </select>

    <label>Quantity (g):</label>
    <input type="number" id="quantityInput" step="0.001" min="0" style="width:100%;">

    <label>Purity (%):</label>
    <input type="number" id="purityInput" step="0.01" min="0" max="100" style="width:100%;">

    <label>Description:</label>
    <textarea id="descArea"></textarea>

    <label>Image URL:</label>
    <input type="text" id="imgUrlInput" placeholder="https://example.com/image.jpg">
    <button id="setUrlBtn">Set URL</button>

    <label>Or upload an Image (max ~2MB):</label>
    <input type="file" id="imgFileInput">
    <button id="uploadBtn">Upload</button>
    <img id="previewImg" alt="No image">
  </div>

  <!-- AUTHOR INFO MODAL -->
  <div id="authorInfoModal">
    <div id="authorInfoContent"></div>
    <button id="authorInfoClose">Close</button>
  </div>

  <script>
    /**************************************************************
     * 1) STATIC ELEMENTS DATA (period/group + briefDesc)
     *    for building the table layout
     **************************************************************/
const elementsData = [
  {
    atomicNumber: 1,
    symbol: "H",
    name: "Hydrogen",
    category: "nonmetal",
    group: 1,
    period: 1,
    atomicMass: 1.008,
    briefDesc: "Lightest element, highly reactive nonmetal"
  },
  {
    atomicNumber: 2,
    symbol: "He",
    name: "Helium",
    category: "noble gas",
    group: 18,
    period: 1,
    atomicMass: 4.002602,
    briefDesc: "Colorless, odorless noble gas used in balloons"
  },
  {
    atomicNumber: 3,
    symbol: "Li",
    name: "Lithium",
    category: "alkali metal",
    group: 1,
    period: 2,
    atomicMass: 6.94,
    briefDesc: "Soft, silvery metal, lightest metal"
  },
  {
    atomicNumber: 4,
    symbol: "Be",
    name: "Beryllium",
    category: "alkaline earth metal",
    group: 2,
    period: 2,
    atomicMass: 9.0121831,
    briefDesc: "Hard, gray metal, toxic in some forms"
  },
  {
    atomicNumber: 5,
    symbol: "B",
    name: "Boron",
    category: "metalloid",
    group: 13,
    period: 2,
    atomicMass: 10.81,
    briefDesc: "Brittle, black metalloid used in semiconductors"
  },
  {
    atomicNumber: 6,
    symbol: "C",
    name: "Carbon",
    category: "nonmetal",
    group: 14,
    period: 2,
    atomicMass: 12.011,
    briefDesc: "Nonmetal with allotropes like diamond & graphite"
  },
  {
    atomicNumber: 7,
    symbol: "N",
    name: "Nitrogen",
    category: "nonmetal",
    group: 15,
    period: 2,
    atomicMass: 14.007,
    briefDesc: "Colorless gas, ~78% of Earth's atmosphere"
  },
  {
    atomicNumber: 8,
    symbol: "O",
    name: "Oxygen",
    category: "nonmetal",
    group: 16,
    period: 2,
    atomicMass: 15.999,
    briefDesc: "Colorless gas essential for aerobic life"
  },
  {
    atomicNumber: 9,
    symbol: "F",
    name: "Fluorine",
    category: "halogen",
    group: 17,
    period: 2,
    atomicMass: 18.998403163,
    briefDesc: "Pale yellow, highly reactive gas"
  },
  {
    atomicNumber: 10,
    symbol: "Ne",
    name: "Neon",
    category: "noble gas",
    group: 18,
    period: 2,
    atomicMass: 20.1797,
    briefDesc: "Inert gas used in neon signs"
  },
  {
    atomicNumber: 11,
    symbol: "Na",
    name: "Sodium",
    category: "alkali metal",
    group: 1,
    period: 3,
    atomicMass: 22.98976928,
    briefDesc: "Soft, reactive metal that tarnishes quickly"
  },
  {
    atomicNumber: 12,
    symbol: "Mg",
    name: "Magnesium",
    category: "alkaline earth metal",
    group: 2,
    period: 3,
    atomicMass: 24.305,
    briefDesc: "Light metal, burns with bright white flame"
  },
  {
    atomicNumber: 13,
    symbol: "Al",
    name: "Aluminum",
    category: "post-transition metal",
    group: 13,
    period: 3,
    atomicMass: 26.9815385,
    briefDesc: "Silvery metal used in aircraft, packaging"
  },
  {
    atomicNumber: 14,
    symbol: "Si",
    name: "Silicon",
    category: "metalloid",
    group: 14,
    period: 3,
    atomicMass: 28.085,
    briefDesc: "Semiconductor metalloid used in electronics"
  },
  {
    atomicNumber: 15,
    symbol: "P",
    name: "Phosphorus",
    category: "nonmetal",
    group: 15,
    period: 3,
    atomicMass: 30.974,
    briefDesc: "Multiple allotropes; vital in biology"
  },
  {
    atomicNumber: 16,
    symbol: "S",
    name: "Sulfur",
    category: "nonmetal",
    group: 16,
    period: 3,
    atomicMass: 32.06,
    briefDesc: "Yellow nonmetal used in sulfuric acid"
  },
  {
    atomicNumber: 17,
    symbol: "Cl",
    name: "Chlorine",
    category: "halogen",
    group: 17,
    period: 3,
    atomicMass: 35.45,
    briefDesc: "Greenish-yellow, reactive gas; used as disinfectant"
  },
  {
    atomicNumber: 18,
    symbol: "Ar",
    name: "Argon",
    category: "noble gas",
    group: 18,
    period: 3,
    atomicMass: 39.948,
    briefDesc: "Inert, colorless gas used in lighting"
  },
  {
    atomicNumber: 19,
    symbol: "K",
    name: "Potassium",
    category: "alkali metal",
    group: 1,
    period: 4,
    atomicMass: 39.0983,
    briefDesc: "Soft, reactive metal essential to biology"
  },
  {
    atomicNumber: 20,
    symbol: "Ca",
    name: "Calcium",
    category: "alkaline earth metal",
    group: 2,
    period: 4,
    atomicMass: 40.078,
    briefDesc: "Vital for bones, silvery metal"
  },
  {
    atomicNumber: 21,
    symbol: "Sc",
    name: "Scandium",
    category: "transition metal",
    group: 3,
    period: 4,
    atomicMass: 44.955908,
    briefDesc: "Light, silvery metal used in alloys"
  },
  {
    atomicNumber: 22,
    symbol: "Ti",
    name: "Titanium",
    category: "transition metal",
    group: 4,
    period: 4,
    atomicMass: 47.867,
    briefDesc: "Strong, light, corrosion-resistant metal"
  },
  {
    atomicNumber: 23,
    symbol: "V",
    name: "Vanadium",
    category: "transition metal",
    group: 5,
    period: 4,
    atomicMass: 50.9415,
    briefDesc: "Used to strengthen steel alloys"
  },
  {
    atomicNumber: 24,
    symbol: "Cr",
    name: "Chromium",
    category: "transition metal",
    group: 6,
    period: 4,
    atomicMass: 51.9961,
    briefDesc: "Lustrous, hard metal for stainless steel"
  },
  {
    atomicNumber: 25,
    symbol: "Mn",
    name: "Manganese",
    category: "transition metal",
    group: 7,
    period: 4,
    atomicMass: 54.938044,
    briefDesc: "Hard, brittle metal used in steel"
  },
  {
    atomicNumber: 26,
    symbol: "Fe",
    name: "Iron",
    category: "transition metal",
    group: 8,
    period: 4,
    atomicMass: 55.845,
    briefDesc: "Most used metal, basis of steel"
  },
  {
    atomicNumber: 27,
    symbol: "Co",
    name: "Cobalt",
    category: "transition metal",
    group: 9,
    period: 4,
    atomicMass: 58.933194,
    briefDesc: "Hard, lustrous, silver-gray metal"
  },
  {
    atomicNumber: 28,
    symbol: "Ni",
    name: "Nickel",
    category: "transition metal",
    group: 10,
    period: 4,
    atomicMass: 58.6934,
    briefDesc: "Silvery metal used in coins, alloys"
  },
  {
    atomicNumber: 29,
    symbol: "Cu",
    name: "Copper",
    category: "transition metal",
    group: 11,
    period: 4,
    atomicMass: 63.546,
    briefDesc: "Reddish metal, excellent electrical conductor"
  },
  {
    atomicNumber: 30,
    symbol: "Zn",
    name: "Zinc",
    category: "transition metal",
    group: 12,
    period: 4,
    atomicMass: 65.38,
    briefDesc: "Bluish-silver metal used to galvanize steel"
  },
  {
    atomicNumber: 31,
    symbol: "Ga",
    name: "Gallium",
    category: "post-transition metal",
    group: 13,
    period: 4,
    atomicMass: 69.723,
    briefDesc: "Soft metal melting near room temp"
  },
  {
    atomicNumber: 32,
    symbol: "Ge",
    name: "Germanium",
    category: "metalloid",
    group: 14,
    period: 4,
    atomicMass: 72.63,
    briefDesc: "Grayish-white metalloid for semiconductors"
  },
  {
    atomicNumber: 33,
    symbol: "As",
    name: "Arsenic",
    category: "metalloid",
    group: 15,
    period: 4,
    atomicMass: 74.921595,
    briefDesc: "Poisonous metalloid with many allotropes"
  },
  {
    atomicNumber: 34,
    symbol: "Se",
    name: "Selenium",
    category: "nonmetal",
    group: 16,
    period: 4,
    atomicMass: 78.971,
    briefDesc: "Nonmetal used in photocopiers, glass"
  },
  {
    atomicNumber: 35,
    symbol: "Br",
    name: "Bromine",
    category: "halogen",
    group: 17,
    period: 4,
    atomicMass: 79.904,
    briefDesc: "Reddish-brown liquid halogen"
  },
  {
    atomicNumber: 36,
    symbol: "Kr",
    name: "Krypton",
    category: "noble gas",
    group: 18,
    period: 4,
    atomicMass: 83.798,
    briefDesc: "Colorless noble gas for lighting"
  },
  {
    atomicNumber: 37,
    symbol: "Rb",
    name: "Rubidium",
    category: "alkali metal",
    group: 1,
    period: 5,
    atomicMass: 85.4678,
    briefDesc: "Very soft, highly reactive metal"
  },
  {
    atomicNumber: 38,
    symbol: "Sr",
    name: "Strontium",
    category: "alkaline earth metal",
    group: 2,
    period: 5,
    atomicMass: 87.62,
    briefDesc: "Silvery metal used in red fireworks"
  },
  {
    atomicNumber: 39,
    symbol: "Y",
    name: "Yttrium",
    category: "transition metal",
    group: 3,
    period: 5,
    atomicMass: 88.90584,
    briefDesc: "Silvery metal used in phosphors"
  },
  {
    atomicNumber: 40,
    symbol: "Zr",
    name: "Zirconium",
    category: "transition metal",
    group: 4,
    period: 5,
    atomicMass: 91.224,
    briefDesc: "Corrosion-resistant metal for nuclear reactors"
  },
  {
    atomicNumber: 41,
    symbol: "Nb",
    name: "Niobium",
    category: "transition metal",
    group: 5,
    period: 5,
    atomicMass: 92.90637,
    briefDesc: "Used in superconducting materials"
  },
  {
    atomicNumber: 42,
    symbol: "Mo",
    name: "Molybdenum",
    category: "transition metal",
    group: 6,
    period: 5,
    atomicMass: 95.95,
    briefDesc: "Hard, silvery metal for steel alloys"
  },
  {
    atomicNumber: 43,
    symbol: "Tc",
    name: "Technetium",
    category: "transition metal",
    group: 7,
    period: 5,
    atomicMass: 98,
    briefDesc: "Radioactive, first artificially made element"
  },
  {
    atomicNumber: 44,
    symbol: "Ru",
    name: "Ruthenium",
    category: "transition metal",
    group: 8,
    period: 5,
    atomicMass: 101.07,
    briefDesc: "Hard, silvery-white transition metal"
  },
  {
    atomicNumber: 45,
    symbol: "Rh",
    name: "Rhodium",
    category: "transition metal",
    group: 9,
    period: 5,
    atomicMass: 102.90550,
    briefDesc: "Highly reflective metal, used in plating"
  },
  {
    atomicNumber: 46,
    symbol: "Pd",
    name: "Palladium",
    category: "transition metal",
    group: 10,
    period: 5,
    atomicMass: 106.42,
    briefDesc: "Rare, lustrous metal in catalytic converters"
  },
  {
    atomicNumber: 47,
    symbol: "Ag",
    name: "Silver",
    category: "transition metal",
    group: 11,
    period: 5,
    atomicMass: 107.8682,
    briefDesc: "Best electrical conductor, lustrous"
  },
  {
    atomicNumber: 48,
    symbol: "Cd",
    name: "Cadmium",
    category: "transition metal",
    group: 12,
    period: 5,
    atomicMass: 112.414,
    briefDesc: "Bluish-white metal, toxic"
  },
  {
    atomicNumber: 49,
    symbol: "In",
    name: "Indium",
    category: "post-transition metal",
    group: 13,
    period: 5,
    atomicMass: 114.818,
    briefDesc: "Soft, malleable, used in LCDs"
  },
  {
    atomicNumber: 50,
    symbol: "Sn",
    name: "Tin",
    category: "post-transition metal",
    group: 14,
    period: 5,
    atomicMass: 118.71,
    briefDesc: "Silvery metal historically used in cans"
  },
  {
    atomicNumber: 51,
    symbol: "Sb",
    name: "Antimony",
    category: "metalloid",
    group: 15,
    period: 5,
    atomicMass: 121.76,
    briefDesc: "Brittle metalloid used in flame retardants"
  },
  {
    atomicNumber: 52,
    symbol: "Te",
    name: "Tellurium",
    category: "metalloid",
    group: 16,
    period: 5,
    atomicMass: 127.6,
    briefDesc: "Brittle, silvery metalloid in semiconductors"
  },
  {
    atomicNumber: 53,
    symbol: "I",
    name: "Iodine",
    category: "halogen",
    group: 17,
    period: 5,
    atomicMass: 126.90447,
    briefDesc: "Purple-black solid halogen, essential nutrient"
  },
  {
    atomicNumber: 54,
    symbol: "Xe",
    name: "Xenon",
    category: "noble gas",
    group: 18,
    period: 5,
    atomicMass: 131.293,
    briefDesc: "Heavy, colorless noble gas, used in flash lamps"
  },
  {
    atomicNumber: 55,
    symbol: "Cs",
    name: "Cesium",
    category: "alkali metal",
    group: 1,
    period: 6,
    atomicMass: 132.90545196,
    briefDesc: "Soft, golden metal, highly reactive"
  },
  {
    atomicNumber: 56,
    symbol: "Ba",
    name: "Barium",
    category: "alkaline earth metal",
    group: 2,
    period: 6,
    atomicMass: 137.327,
    briefDesc: "Silvery metal used in X-ray contrast agents"
  },
  {
    atomicNumber: 57,
    symbol: "La",
    name: "Lanthanum",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 138.90547,
    briefDesc: "Soft, ductile metal, starts lanthanide series"
  },
  {
    atomicNumber: 58,
    symbol: "Ce",
    name: "Cerium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 140.116,
    briefDesc: "Most abundant lanthanide, used in converters"
  },
  {
    atomicNumber: 59,
    symbol: "Pr",
    name: "Praseodymium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 140.90766,
    briefDesc: "Soft, silvery lanthanide used in magnets"
  },
  {
    atomicNumber: 60,
    symbol: "Nd",
    name: "Neodymium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 144.242,
    briefDesc: "Used in powerful rare-earth magnets"
  },
  {
    atomicNumber: 61,
    symbol: "Pm",
    name: "Promethium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 145,
    briefDesc: "Radioactive, no stable isotopes"
  },
  {
    atomicNumber: 62,
    symbol: "Sm",
    name: "Samarium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 150.36,
    briefDesc: "Used in magnets and nuclear reactors"
  },
  {
    atomicNumber: 63,
    symbol: "Eu",
    name: "Europium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 151.964,
    briefDesc: "Most reactive lanthanide, used in phosphors"
  },
  {
    atomicNumber: 64,
    symbol: "Gd",
    name: "Gadolinium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 157.25,
    briefDesc: "Used in MRI contrast, has special magnetic properties"
  },
  {
    atomicNumber: 65,
    symbol: "Tb",
    name: "Terbium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 158.925354,
    briefDesc: "Used in green phosphors & devices"
  },
  {
    atomicNumber: 66,
    symbol: "Dy",
    name: "Dysprosium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 162.5,
    briefDesc: "Silvery metal for lasers, magnets"
  },
  {
    atomicNumber: 67,
    symbol: "Ho",
    name: "Holmium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 164.930328,
    briefDesc: "Used in nuclear reactors & special alloys"
  },
  {
    atomicNumber: 68,
    symbol: "Er",
    name: "Erbium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 167.259,
    briefDesc: "Used in optical fibers & amplifiers"
  },
  {
    atomicNumber: 69,
    symbol: "Tm",
    name: "Thulium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 168.934218,
    briefDesc: "Rare, used in some lasers"
  },
  {
    atomicNumber: 70,
    symbol: "Yb",
    name: "Ytterbium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 173.045,
    briefDesc: "Soft, silvery metal used in some steels"
  },
  {
    atomicNumber: 71,
    symbol: "Lu",
    name: "Lutetium",
    category: "lanthanide",
    group: 3,
    period: 6,
    atomicMass: 174.9668,
    briefDesc: "Hard, silvery-white metal, end of lanthanides"
  },
  {
    atomicNumber: 72,
    symbol: "Hf",
    name: "Hafnium",
    category: "transition metal",
    group: 4,
    period: 6,
    atomicMass: 178.49,
    briefDesc: "Used in nuclear control rods, very corrosion-resistant"
  },
  {
    atomicNumber: 73,
    symbol: "Ta",
    name: "Tantalum",
    category: "transition metal",
    group: 5,
    period: 6,
    atomicMass: 180.94788,
    briefDesc: "Blue-gray metal, highly corrosion-resistant"
  },
  {
    atomicNumber: 74,
    symbol: "W",
    name: "Tungsten",
    category: "transition metal",
    group: 6,
    period: 6,
    atomicMass: 183.84,
    briefDesc: "Highest melting point of all elements"
  },
  {
    atomicNumber: 75,
    symbol: "Re",
    name: "Rhenium",
    category: "transition metal",
    group: 7,
    period: 6,
    atomicMass: 186.207,
    briefDesc: "Rare metal used in superalloys"
  },
  {
    atomicNumber: 76,
    symbol: "Os",
    name: "Osmium",
    category: "transition metal",
    group: 8,
    period: 6,
    atomicMass: 190.23,
    briefDesc: "Densest naturally occurring element"
  },
  {
    atomicNumber: 77,
    symbol: "Ir",
    name: "Iridium",
    category: "transition metal",
    group: 9,
    period: 6,
    atomicMass: 192.217,
    briefDesc: "Very hard, brittle metal with high melting point"
  },
  {
    atomicNumber: 78,
    symbol: "Pt",
    name: "Platinum",
    category: "transition metal",
    group: 10,
    period: 6,
    atomicMass: 195.084,
    briefDesc: "Precious, dense, malleable metal for catalysts"
  },
  {
    atomicNumber: 79,
    symbol: "Au",
    name: "Gold",
    category: "transition metal",
    group: 11,
    period: 6,
    atomicMass: 196.966569,
    briefDesc: "Soft, yellow metal, highly valued precious metal"
  },
  {
    atomicNumber: 80,
    symbol: "Hg",
    name: "Mercury",
    category: "transition metal",
    group: 12,
    period: 6,
    atomicMass: 200.592,
    briefDesc: "Silvery metal, liquid at room temperature"
  },
  {
    atomicNumber: 81,
    symbol: "Tl",
    name: "Thallium",
    category: "post-transition metal",
    group: 13,
    period: 6,
    atomicMass: 204.38,
    briefDesc: "Soft, gray metal, highly toxic"
  },
  {
    atomicNumber: 82,
    symbol: "Pb",
    name: "Lead",
    category: "post-transition metal",
    group: 14,
    period: 6,
    atomicMass: 207.2,
    briefDesc: "Soft, malleable metal used in batteries"
  },
  {
    atomicNumber: 83,
    symbol: "Bi",
    name: "Bismuth",
    category: "post-transition metal",
    group: 15,
    period: 6,
    atomicMass: 208.98040,
    briefDesc: "Brittle metal, low toxicity, used in meds"
  },
  {
    atomicNumber: 84,
    symbol: "Po",
    name: "Polonium",
    category: "metalloid",
    group: 16,
    period: 6,
    atomicMass: 209,
    briefDesc: "Radioactive metalloid discovered by Curie"
  },
  {
    atomicNumber: 85,
    symbol: "At",
    name: "Astatine",
    category: "halogen",
    group: 17,
    period: 6,
    atomicMass: 210,
    briefDesc: "Rare, radioactive halogen"
  },
  {
    atomicNumber: 86,
    symbol: "Rn",
    name: "Radon",
    category: "noble gas",
    group: 18,
    period: 6,
    atomicMass: 222,
    briefDesc: "Radioactive, colorless noble gas"
  },
  {
    atomicNumber: 87,
    symbol: "Fr",
    name: "Francium",
    category: "alkali metal",
    group: 1,
    period: 7,
    atomicMass: 223,
    briefDesc: "Extremely reactive, radioactive alkali metal"
  },
  {
    atomicNumber: 88,
    symbol: "Ra",
    name: "Radium",
    category: "alkaline earth metal",
    group: 2,
    period: 7,
    atomicMass: 226,
    briefDesc: "Radioactive, glows faintly in the dark"
  },
  {
    atomicNumber: 89,
    symbol: "Ac",
    name: "Actinium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 227,
    briefDesc: "Radioactive, starts the actinide series"
  },
  {
    atomicNumber: 90,
    symbol: "Th",
    name: "Thorium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 232.0377,
    briefDesc: "Potential nuclear fuel, slightly radioactive"
  },
  {
    atomicNumber: 91,
    symbol: "Pa",
    name: "Protactinium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 231.03588,
    briefDesc: "Rare, radioactive actinide"
  },
  {
    atomicNumber: 92,
    symbol: "U",
    name: "Uranium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 238.02891,
    briefDesc: "Radioactive, used in nuclear power & weapons"
  },
  {
    atomicNumber: 93,
    symbol: "Np",
    name: "Neptunium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 237,
    briefDesc: "Transuranic, radioactive actinide"
  },
  {
    atomicNumber: 94,
    symbol: "Pu",
    name: "Plutonium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 244,
    briefDesc: "Transuranic, radioactive, used in nuclear bombs"
  },
  {
    atomicNumber: 95,
    symbol: "Am",
    name: "Americium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 243,
    briefDesc: "Radioactive, used in smoke detectors"
  },
  {
    atomicNumber: 96,
    symbol: "Cm",
    name: "Curium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 247,
    briefDesc: "Transuranic, radioactive metal"
  },
  {
    atomicNumber: 97,
    symbol: "Bk",
    name: "Berkelium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 247,
    briefDesc: "Transuranic, synthetic radioactive actinide"
  },
  {
    atomicNumber: 98,
    symbol: "Cf",
    name: "Californium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 251,
    briefDesc: "Transuranic, used to start nuclear reactors"
  },
  {
    atomicNumber: 99,
    symbol: "Es",
    name: "Einsteinium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 252,
    briefDesc: "Synthetic, radioactive metal"
  },
  {
    atomicNumber: 100,
    symbol: "Fm",
    name: "Fermium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 257,
    briefDesc: "Synthetic, radioactive actinide"
  },
  {
    atomicNumber: 101,
    symbol: "Md",
    name: "Mendelevium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 258,
    briefDesc: "Synthetic, radioactive actinide"
  },
  {
    atomicNumber: 102,
    symbol: "No",
    name: "Nobelium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 259,
    briefDesc: "Synthetic, radioactive actinide"
  },
  {
    atomicNumber: 103,
    symbol: "Lr",
    name: "Lawrencium",
    category: "actinide",
    group: 3,
    period: 7,
    atomicMass: 266,
    briefDesc: "Synthetic, radioactive metal"
  },
  {
    atomicNumber: 104,
    symbol: "Rf",
    name: "Rutherfordium",
    category: "transition metal",
    group: 4,
    period: 7,
    atomicMass: 267,
    briefDesc: "Synthetic, radioactive transition metal"
  },
  {
    atomicNumber: 105,
    symbol: "Db",
    name: "Dubnium",
    category: "transition metal",
    group: 5,
    period: 7,
    atomicMass: 268,
    briefDesc: "Synthetic, radioactive transition metal"
  },
  {
    atomicNumber: 106,
    symbol: "Sg",
    name: "Seaborgium",
    category: "transition metal",
    group: 6,
    period: 7,
    atomicMass: 269,
    briefDesc: "Synthetic, radioactive transition metal"
  },
  {
    atomicNumber: 107,
    symbol: "Bh",
    name: "Bohrium",
    category: "transition metal",
    group: 7,
    period: 7,
    atomicMass: 270,
    briefDesc: "Synthetic, radioactive transition metal"
  },
  {
    atomicNumber: 108,
    symbol: "Hs",
    name: "Hassium",
    category: "transition metal",
    group: 8,
    period: 7,
    atomicMass: 269,
    briefDesc: "Synthetic, radioactive transition metal"
  },
  {
    atomicNumber: 109,
    symbol: "Mt",
    name: "Meitnerium",
    category: "transition metal",
    group: 9,
    period: 7,
    atomicMass: 278,
    briefDesc: "Synthetic, radioactive transition metal"
  },
  {
    atomicNumber: 110,
    symbol: "Ds",
    name: "Darmstadtium",
    category: "transition metal",
    group: 10,
    period: 7,
    atomicMass: 281,
    briefDesc: "Synthetic, radioactive transition metal"
  },
  {
    atomicNumber: 111,
    symbol: "Rg",
    name: "Roentgenium",
    category: "transition metal",
    group: 11,
    period: 7,
    atomicMass: 282,
    briefDesc: "Synthetic, radioactive transition metal"
  },
  {
    atomicNumber: 112,
    symbol: "Cn",
    name: "Copernicium",
    category: "post-transition metal",
    group: 12,
    period: 7,
    atomicMass: 285,
    briefDesc: "Synthetic, radioactive post-transition metal"
  },
  {
    atomicNumber: 113,
    symbol: "Nh",
    name: "Nihonium",
    category: "post-transition metal",
    group: 13,
    period: 7,
    atomicMass: 286,
    briefDesc: "Synthetic, radioactive post-transition metal"
  },
  {
    atomicNumber: 114,
    symbol: "Fl",
    name: "Flerovium",
    category: "post-transition metal",
    group: 14,
    period: 7,
    atomicMass: 289,
    briefDesc: "Synthetic, radioactive post-transition metal"
  },
  {
    atomicNumber: 115,
    symbol: "Mc",
    name: "Moscovium",
    category: "post-transition metal",
    group: 15,
    period: 7,
    atomicMass: 289,
    briefDesc: "Synthetic, radioactive post-transition metal"
  },
  {
    atomicNumber: 116,
    symbol: "Lv",
    name: "Livermorium",
    category: "post-transition metal",
    group: 16,
    period: 7,
    atomicMass: 293,
    briefDesc: "Synthetic, radioactive post-transition metal"
  },
  {
    atomicNumber: 117,
    symbol: "Ts",
    name: "Tennessine",
    category: "halogen",
    group: 17,
    period: 7,
    atomicMass: 294,
    briefDesc: "Synthetic, radioactive halogen"
  },
  {
    atomicNumber: 118,
    symbol: "Og",
    name: "Oganesson",
    category: "noble gas",
    group: 18,
    period: 7,
    atomicMass: 294,
    briefDesc: "Synthetic, heaviest noble gas known"
  }
];

    /**************************************************************
     * 2) RUNTIME VARIABLES
     **************************************************************/
    let isLoggedIn      = false;
    let loggedInUser    = null;
    let isViewingPublic = false;
    let viewedUser      = null;

    // elementData => user’s statuses: { "H": {status, description, imageUrl, quantity, purity, ... }, ... }
    let elementData     = {};

    let currentSymbol   = null;
    let quickStatusMode = false;
    let quickStatusValue= "";
    let myChart         = null;

    const userStatusBar = document.getElementById("userStatusBar");
    const logoutBtn     = document.getElementById("logoutBtn");
    const detailsPanel  = document.getElementById("detailsPanel");

    /**************************************************************
     * 3) BUILD THE MAIN TABLE, LAN/ACT SUBTABLES
     **************************************************************/
    function buildMainTable(){
      const table=document.getElementById("periodicTable");
      table.innerHTML="";
      const maxPeriod=7, maxGroup=18;
      for(let p=1; p<=maxPeriod; p++){
        const tr=document.createElement("tr");
        for(let g=1; g<=maxGroup; g++){
          const td=document.createElement("td");
          // skip lanthanides/actinides in main
          const el=elementsData.find(e=>{
            if(e.period===p && e.group===g){
              if((e.atomicNumber>=57 && e.atomicNumber<=71)||(e.atomicNumber>=89 && e.atomicNumber<=103)){
                return false;
              }
              return true;
            }
            return false;
          });
          if(el) {
            populateCell(td, el);
          } else {
            td.style.background='#f8f8f8';
            td.style.cursor='default';
          }
          tr.appendChild(td);
        }
        table.appendChild(tr);
      }
    }
    function buildLanthanideTable(){
      const lt=document.getElementById("lanthanideTable");
      lt.innerHTML="";
      const row=document.createElement("tr");
      for(let z=57; z<=71; z++){
        const td=document.createElement("td");
        const el=elementsData.find(e=>e.atomicNumber===z);
        if(el) populateCell(td, el);
        row.appendChild(td);
      }
      lt.appendChild(row);
    }
    function buildActinideTable(){
      const at=document.getElementById("actinideTable");
      at.innerHTML="";
      const row=document.createElement("tr");
      for(let z=89; z<=103; z++){
        const td=document.createElement("td");
        const el=elementsData.find(e=>e.atomicNumber===z);
        if(el) populateCell(td, el);
        row.appendChild(td);
      }
      at.appendChild(row);
    }

    function getCategoryOutlineColor(cat){
      switch(cat){
        case 'alkali metal': return '#FFB347';
        case 'alkaline earth metal': return '#FFDB58';
        case 'transition metal': return '#C0C0C0';
        case 'post-transition metal': return '#FFD700';
        case 'metalloid': return '#ADFF2F';
        case 'nonmetal': return '#77DD77';
        case 'halogen': return '#ffb3ba';
        case 'noble gas': return '#FFC0CB';
        case 'lanthanide': return '#ffcc99';
        case 'actinide': return '#ff9999';
        default: return '#999';
      }
    }

    function populateCell(cell, el){
      cell.textContent=el.symbol;
      const numSpan=document.createElement("span");
      numSpan.className="atomic-number";
      numSpan.textContent=el.atomicNumber;
      cell.appendChild(numSpan);

      // Outline => category
      const catColor=getCategoryOutlineColor(el.category);
      cell.style.outline=`3px solid ${catColor}`;
      cell.style.outlineOffset='-3px';

      cell.dataset.symbol=el.symbol;
      cell.dataset.name=el.name;

      cell.addEventListener("mouseover",(e)=>{
        const tip=document.getElementById("elementTooltip");
        tip.innerHTML=`
          <strong>${el.name}</strong> [${el.symbol}]<br>
          ${el.briefDesc||''}
        `;
        tip.style.display='block';
        tip.style.left=(e.pageX+10)+'px';
        tip.style.top=(e.pageY+10)+'px';
      });
      cell.addEventListener("mousemove",(e)=>{
        const tip=document.getElementById("elementTooltip");
        tip.style.left=(e.pageX+10)+'px';
        tip.style.top=(e.pageY+10)+'px';
      });
      cell.addEventListener("mouseout",()=>{
        document.getElementById("elementTooltip").style.display='none';
      });
      cell.addEventListener("click",()=>{
        if(isViewingPublic){
          // read-only
          openDetailsFor(el.symbol, true);
        } else if(quickStatusMode && isLoggedIn){
          setElementStatus(el.symbol, quickStatusValue);
        } else if(!quickStatusMode){
          openDetailsFor(el.symbol, false);
        } else {
          alert("You must be logged in to modify statuses.");
        }
      });
    }

    /**************************************************************
     * 4) STATUS & DETAILS PANEL
     **************************************************************/
    function setElementStatus(symbol,status){
      if(!elementData[symbol]){
        elementData[symbol]={status:'',description:'',imageUrl:'',quantity:0,purity:100};
      }
      elementData[symbol].status=status;
      refreshStatuses();
      updateCounters();
    }

    function refreshStatuses(){
      const mainCells=[...document.querySelectorAll('#periodicTable td[data-symbol]')];
      const lanCells =[...document.querySelectorAll('#lanthanideTable td[data-symbol]')];
      const actCells =[...document.querySelectorAll('#actinideTable td[data-symbol]')];
      const allCells = mainCells.concat(lanCells,actCells);

      allCells.forEach(cell=>{
        cell.classList.remove("status-pure","status-rep","status-alloy","status-wish");
        const sym=cell.dataset.symbol;
        const rec=elementData[sym];
        if(rec && rec.status){
          if(rec.status==="Pure")               cell.classList.add("status-pure");
          else if(rec.status==="Representative")cell.classList.add("status-rep");
          else if(rec.status==="Alloy")         cell.classList.add("status-alloy");
          else if(rec.status==="Wish")          cell.classList.add("status-wish");
        }
      });
    }

    document.getElementById("quickStatusCheckbox").addEventListener("change", e=>{
      quickStatusMode=e.target.checked;
    });
    document.getElementById("quickStatusDropdown").addEventListener("change", e=>{
      quickStatusValue=e.target.value;
    });

    function openDetailsFor(symbol, readOnly){
      currentSymbol=symbol;
      // find static element info
      const el=elementsData.find(e=>e.symbol===symbol);
      // find or create user’s record
      const rec=elementData[symbol] || {status:'',description:'',imageUrl:'',quantity:0,purity:100};

      detailsPanel.classList.remove("edit-mode","view-mode");
      if(readOnly){
        detailsPanel.classList.add("view-mode");
      } else {
        detailsPanel.classList.add("edit-mode");
      }

      document.getElementById("elementTitle").textContent =
        el ? `${el.name} (${el.symbol})` : symbol;

      ["statusSelect","descArea","imgUrlInput","setUrlBtn","imgFileInput",
       "uploadBtn","quantityInput","purityInput"].forEach(id=>{
         document.getElementById(id).disabled = readOnly;
       });

      document.getElementById("statusSelect").value     = rec.status||'';
      document.getElementById("descArea").value         = rec.description||'';
      document.getElementById("quantityInput").value    = rec.quantity||0;
      document.getElementById("purityInput").value      = rec.purity||100;
      document.getElementById("imgUrlInput").value      = rec.imageUrl||'';

      const pv=document.getElementById("previewImg");
      if(rec.imageUrl){
        pv.src=rec.imageUrl;
        pv.style.display='block';
      } else {
        pv.src='';
        pv.style.display='none';
      }
      refreshStatuses();
    }

    document.getElementById("statusSelect").addEventListener("change", updateCurrentElementRecord);
    document.getElementById("descArea").addEventListener("input", updateCurrentElementRecord);
    document.getElementById("quantityInput").addEventListener("change", updateCurrentElementRecord);
    document.getElementById("purityInput").addEventListener("change", updateCurrentElementRecord);

    function updateCurrentElementRecord(){
      if(!currentSymbol || !isLoggedIn) return;
      if(!elementData[currentSymbol]){
        elementData[currentSymbol]={status:'',description:'',imageUrl:'',quantity:0,purity:100};
      }
      const rec=elementData[currentSymbol];
      rec.status      = document.getElementById("statusSelect").value||'';
      rec.description = document.getElementById("descArea").value||'';
      rec.imageUrl    = document.getElementById("imgUrlInput").value||'';
      rec.quantity    = Number(document.getElementById("quantityInput").value)||0;
      rec.purity      = Number(document.getElementById("purityInput").value)||100;
      updateCounters();
      refreshStatuses();
    }

    document.getElementById("setUrlBtn").addEventListener("click",()=>{
      if(!isLoggedIn){
        alert("You must be logged in to set an image URL.");
        return;
      }
      updateCurrentElementRecord();
      const url=document.getElementById("imgUrlInput").value;
      const pv=document.getElementById("previewImg");
      if(url){
        pv.src=url;
        pv.style.display='block';
      } else {
        pv.src='';
        pv.style.display='none';
      }
    });

    document.getElementById("uploadBtn").addEventListener("click", async ()=>{
      if(!isLoggedIn){
        alert("Login first.");
        return;
      }
      if(!currentSymbol){
        alert("Select an element first.");
        return;
      }
      const fi=document.getElementById("imgFileInput");
      if(!fi.files||!fi.files[0]){
        alert("No file selected.");
        return;
      }
      const formData=new FormData();
      formData.append("image", fi.files[0]);

      try{
        const resp=await fetch(`/upload/${encodeURIComponent(currentSymbol)}`,{
          method:"POST",credentials:"include",body:formData
        });
        const data=await resp.json();
        if(data.status==="success"){
          alert("Uploaded!");
          if(!elementData[currentSymbol]){
            elementData[currentSymbol]={status:'',description:'',imageUrl:'',quantity:0,purity:100};
          }
          elementData[currentSymbol].imageUrl=data.imageUrl;
          document.getElementById("imgUrlInput").value=data.imageUrl;
          const pv=document.getElementById("previewImg");
          pv.src=data.imageUrl;
          pv.style.display='block';
          refreshStatuses();
        } else {
          alert("Upload error: "+(data.message||'Unknown'));
        }
      }catch(err){
        alert("Upload request failed: "+err);
      }
    });

    /**************************************************************
     * 5) COUNTERS & PIE CHART
     **************************************************************/
    function updateCounters(){
      let pure=0,rep=0,alloy=0,wish=0;
      for(const sym in elementData){
        const st=elementData[sym].status;
        if(st==="Pure")              pure++;
        else if(st==="Representative")rep++;
        else if(st==="Alloy")        alloy++;
        else if(st==="Wish")         wish++;
      }
      document.getElementById("counters").textContent =
        `Pure:${pure}, Rep:${rep}, Alloy:${alloy}, Wish:${wish}, Total:${pure+rep+alloy+wish}`;
      showPieChart(pure,rep,alloy,wish);
    }

    function showPieChart(pure,rep,alloy,wish){
      const ctx=document.getElementById("statusChart").getContext("2d");
      if(myChart) myChart.destroy();
      myChart=new Chart(ctx,{
        type:"pie",
        data:{
          labels:["Pure","Rep","Alloy","Wish"],
          datasets:[{
            data:[pure,rep,alloy,wish],
            backgroundColor:["green","orange","blue","purple"]
          }]
        },
        options:{
          responsive:true,
          plugins:{ legend:{position:"bottom"} }
        }
      });
    }

    /**************************************************************
     * 6) LOGIN / LOGOUT / LOAD / SAVE
     **************************************************************/
    document.getElementById("loginLoadBtn").addEventListener("click", loginAndLoad);
    async function loginAndLoad(){
      const username=document.getElementById("usernameInput").value.trim();
      const password=document.getElementById("passwordInput").value;
      if(!username||!password){
        alert("Enter username and password.");
        return;
      }
      try{
        // 1) attempt login
        let resp=await fetch("/auth/login",{
          method:"POST",
          credentials:"include",
          headers:{"Content-Type":"application/json"},
          body: JSON.stringify({username,password})
        });
        let data=await resp.json();
        if(data.status!=="success"){
          alert("Login error: "+(data.message||"Unknown"));
          return;
        }
        alert("Logged in!");
        isLoggedIn=true;
        loggedInUser=username;
        isViewingPublic=false;
        viewedUser=null;
        logoutBtn.style.display='inline-block';
        updateUserStatusBar();
        detailsPanel.classList.remove("view-mode");
        detailsPanel.classList.add("edit-mode");

        // 2) now load /user
        alert("Loading your data...");
        resp=await fetch("/user",{credentials:"include"});
        data=await resp.json();
        if(data.status==="success"){
          elementData = data.statuses||{};
          updateCounters();
          refreshStatuses();
          alert("Data loaded for user: "+username);
        } else {
          alert("Could not load data: "+(data.message||"Unknown"));
        }
      }catch(err){
        alert("Login request failed: "+err);
      }
    }

    document.getElementById("saveBtn").addEventListener("click", saveData);
    async function saveData(){
      if(!isLoggedIn){
        alert("You must be logged in to save.");
        return;
      }
      try{
        const resp=await fetch("/user",{
          method:"POST",
          credentials:"include",
          headers:{"Content-Type":"application/json"},
          body: JSON.stringify({statuses: elementData})
        });
        const data=await resp.json();
        if(data.status==="success"){
          alert("Data saved (DB updated).");
        } else {
          alert("Save error: "+(data.message||"Unknown"));
        }
      }catch(err){
        alert("Save request failed: "+err);
      }
    }

    async function logoutUser(){
      try{
        const resp=await fetch("/auth/logout",{method:"POST",credentials:"include"});
        const data=await resp.json();
        if(data.status==="success"){
          alert("Logged out.");
          isLoggedIn=false;
          loggedInUser=null;
          isViewingPublic=false;
          viewedUser=null;
          elementData={};
          updateCounters();
          refreshStatuses();
          logoutBtn.style.display='none';
          updateUserStatusBar();
          detailsPanel.classList.remove("edit-mode");
          detailsPanel.classList.add("view-mode");
        }
      }catch(err){
        alert("Logout failed: "+err);
      }
    }
    document.getElementById("logoutBtn").addEventListener("click", logoutUser);

    /**************************************************************
     * 7) VIEW PUBLIC => /public/username
     **************************************************************/
    document.getElementById("viewBtn").addEventListener("click", viewPublic);
    async function viewPublic(){
      const user=document.getElementById("viewUsernameInput").value.trim();
      if(!user){
        alert("Enter a username to view.");
        return;
      }
      try{
        const resp=await fetch("/public/"+encodeURIComponent(user),{credentials:"include"});
        const data=await resp.json();
        if(data.status==="success"){
          alert("Loaded public collection of "+user);
          isLoggedIn=false;
          loggedInUser=null;
          isViewingPublic=true;
          viewedUser=user;
          elementData=data.statuses||{};
          updateCounters();
          refreshStatuses();
          logoutBtn.style.display='none';
          updateUserStatusBar();
          detailsPanel.classList.remove("edit-mode");
          detailsPanel.classList.add("view-mode");
        } else {
          alert("View error: "+(data.message||"Unknown"));
        }
      }catch(err){
        alert("Failed to view user's data: "+err);
      }
    }

    /**************************************************************
     * 8) SEARCH
     **************************************************************/
    document.getElementById("searchBtn").addEventListener("click",()=>{
      const q=document.getElementById("searchInput").value.trim().toLowerCase();
      if(!q)return;
      const mainCells=[...document.querySelectorAll('#periodicTable td[data-symbol]')];
      const lanCells =[...document.querySelectorAll('#lanthanideTable td[data-symbol]')];
      const actCells =[...document.querySelectorAll('#actinideTable td[data-symbol]')];
      const allCells = mainCells.concat(lanCells, actCells);
      const found=allCells.find(td=>{
        const s=td.dataset.symbol.toLowerCase();
        const nm=td.dataset.name.toLowerCase();
        return s.includes(q)||nm.includes(q);
      });
      if(found){
        found.scrollIntoView({behavior:"smooth",block:"center"});
        found.style.outline="2px solid orange";
        setTimeout(()=>{found.style.outline="";},2000);
      } else {
        alert("No match found.");
      }
    });

    /**************************************************************
     * 9) AUTHOR INFO MODAL
     **************************************************************/
    document.getElementById("viewOwnerInfoBtn").addEventListener("click", async ()=>{
      if(!viewedUser){
        alert("Must be viewing a public user.");
        return;
      }
      try{
        const resp=await fetch("/publicinfo/"+encodeURIComponent(viewedUser),{credentials:"include"});
        const data=await resp.json();
        if(data.status==="success"){
          let html=`<h2>${data.display_name}</h2>`;
          if(data.bio) html+=`<p>${data.bio}</p>`;
          if(data.profile_image_url) html+=`<img src="${data.profile_image_url}" alt="Profile">`;
          document.getElementById("authorInfoContent").innerHTML=html;
        } else {
          document.getElementById("authorInfoContent").innerHTML=`<p>Error: ${data.message||''}</p>`;
        }
        document.getElementById("authorInfoModal").style.display='block';
      } catch(err){
        alert("Failed to fetch author info: "+err);
      }
    });
    document.getElementById("authorInfoClose").addEventListener("click",()=>{
      document.getElementById("authorInfoModal").style.display='none';
    });

    /**************************************************************
     * 10) DARK MODE
     **************************************************************/
    document.getElementById("darkModeToggle").addEventListener("click",()=>{
      document.body.classList.toggle("dark-mode");
    });

    /**************************************************************
     * 11) USER STATUS BAR
     **************************************************************/
    function updateUserStatusBar(){
      if(isViewingPublic && viewedUser){
        userStatusBar.textContent = `Viewing public collection of: ${viewedUser}`;
      } else if(isLoggedIn && loggedInUser){
        userStatusBar.textContent = `Logged in as: ${loggedInUser}`;
      } else {
        userStatusBar.textContent = "Not logged in.";
      }
    }

    /**************************************************************
     * 12) On Page Load
     **************************************************************/
    window.addEventListener("load",()=>{
      buildMainTable();
      buildLanthanideTable();
      buildActinideTable();
      refreshStatuses();
      updateCounters();
      updateUserStatusBar();
    });
  </script>
</body>
</html>
