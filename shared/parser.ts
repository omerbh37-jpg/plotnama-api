// shared/parser.ts
// One source of truth for both web + mobile.
// Pulled from your dealerbook.html logic, but made DOM-free.

// ===== Types =====
export type BlockOutputStyle = "title" | "letter";
export interface ParseOptions {
  blockOutputStyle?: BlockOutputStyle;     // "title" = "Block F" (default), "letter" = "F block"
  societyDictCSV?: string;                 // if omitted, uses DEFAULT_SOC_DICT
  aliasesJSON?: Record<string, any> | null;// if omitted, uses DEFAULT_ALIASES
}
export interface ParsedResult {
  society: string;
  phase_block: string;
  plot_no: string;
  size_val: number | "";
  size_unit: string;        // Dim text if unknown (e.g., "30*17")
  demand_pkr: number | "";
  demand_text: string;
  phone_e164: string;
  notes: string;
  flags: { corner?: boolean; park?: boolean; possession?: boolean };
  dimensions?: string;      // e.g., 25x50 / 30*90 / 28/55
}

// ===== Helpers (ported) =====
export const DEFAULT_ALIASES = {

  "Bahria Town Rawalpindi": { "Phase 7": ["BHT 7", "BT P7", "Bahria P7", "Bahria Town Phase 7"] },
  "Faisal Hills": { "Executive": ["FH Executive", "FH Executive Block", "Executive Block"] },
  "Multi Gardens B-17": { "Block F": ["B17 F", "Multi Garden F", "B-17 F"] }
};

export const DEFAULT_SOC_DICT = `Bahria Town Karachi : BTK, Bahria Karachi, BT Karachi
DHA Lahore : DHA LHR, Defence Lahore
Bahria Town Rawalpindi : BTR, Bahria Pindi, Bahria Rwp
Gulberg Islamabad : GI, Gulberg Isb
Multi Gardens B-17 : MG B-17, Multi Garden, MPCHS B-17, B-17
Faisal Hills : FH, FH{block}, FH{name}, Faisal Hills Taxila`;

function escRe(s: string){ return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
// ===== Fallback helpers (used only if the primary parser didn't set a value) =====

// A: detect "123 series" or "123series" (2–4 digits) and return normalized "123 series"
const RE_PLOT_SERIES = /\b(\d{2,4})\s*-?\s*series\b/i;

// B: detect a 2–4 digit standalone number that is NOT followed/preceded by size/streets/units/series,
//    so we can treat it as a plot number when no '#' is present.
const RE_STANDALONE_PLOT_NUM =
  /(?:^|\b)(\d{2,4})(?:\b(?!\s*(marla|marla\s*plot|sq|square|yd|yard|yds|feet|ft|x|by|street|st|series)))/i;

// C: accept non-standard marla sizes like "15 marla", "22.5 marla", "7.75 m"
const RE_FLEX_MARLA = /(\d{1,3}(?:\.\d+)?)\s*(marla|mrl|m)\b/i;

// D: block/phase preference
//    - Prefer "F Block" / "G Block" etc (letter before Block)
//    - Also accept "Block C" forms
//    - Avoid "Size Block" false positives
const RE_BLOCK_LETTER_BEFORE = /\b([A-Z])\s*Block\b/i;     // e.g., "F Block"
const RE_BLOCK_AFTER_WORD    = /\bBlock\s*([A-Z0-9-]+)\b/i; // e.g., "Block C", "Block B-17"
const RE_SIZE_BLOCK_PHRASE   = /\b(?:Size\s*Block|Plot\s*Size\s*Block)\b/i;


function formatBlock(letter: string, style: BlockOutputStyle = "title"){
  const L = String(letter||"").toUpperCase();
  if (!L) return "";
  return style === "letter" ? `${L} block` : `Block ${L}`;
}
function labelBlock(blockOrName: string, style: BlockOutputStyle = "title"){
  if(!blockOrName) return "";
  const s = String(blockOrName).trim();
  if(/^[A-Za-z]$/.test(s)) return formatBlock(s, style);
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}
export function toE164(pk: string){
  const d = (pk||"").replace(/\D/g,"");
  if(!d) return "";
  if(d.startsWith("92")) return "+"+d;
  if(d.startsWith("0"))  return "+92"+d.slice(1);
  if(d.startsWith("3") && d.length===10) return "+92"+d;
  return "+"+d;
}

// ===== Dictionary (CSV) =====
export function parseSocietyCSV(csv: string){
  const map = new Map<string, Set<string>>();
  (csv || "").split(/\r?\n/).forEach(line=>{
    const trimmed = line.trim();
    if(!trimmed) return;
    const parts = trimmed.split(":");
    if(parts.length < 2) return;
    const left = parts.shift()!;
    const right = parts.join(":");
    const canonical = (left||"").trim();
    const aliases = (right||"").split(",").map(s=>s.trim()).filter(Boolean);
    if(!canonical) return;
    if(!map.has(canonical)) map.set(canonical, new Set());
    const set = map.get(canonical)!;
    aliases.forEach(a=> set.add(a));
    set.add(canonical);
  });
  return map;
}
function findSocietyFromDict(text: string, csv: string){
  const map = parseSocietyCSV(csv || DEFAULT_SOC_DICT);
  const t = text; // regexes use /i
  for (const [canonical, set] of map.entries()){
    for (const aliasRaw of set){
      const alias = (aliasRaw || "").trim();
      if (!alias) continue;

      if (/\{block\}/i.test(alias)){
        const base = alias.replace(/\{block\}/i, "");
        const rx = new RegExp(`\\b${escRe(base)}([A-Z])\\b`, "i");
        const m = rx.exec(t);
        if (m) return { society: canonical, block: m[1].toUpperCase() };
        continue;
      }
      if (/\{name\}/i.test(alias)){
        const base = alias.replace(/\{name\}/i, "");
        const rx = new RegExp(`\\b${escRe(base)}\\s+([A-Za-z]+)\\b`, "i");
        const m = rx.exec(t);
        if (m) return { society: canonical, block: m[1] };
        continue;
      }
      if (alias.length >= 2){
        const rx = new RegExp(`\\b${escRe(alias)}\\b`, "i");
        if (rx.test(t)) return { society: canonical, block: "" };
      }
    }
  }
  return { society: "", block: "" };
}

// ===== Aliases JSON (advanced) =====
function matchAliases(
  text: string,
  aliasesJSON?: Record<string, any> | null
){
  // Force a dictionary shape that TS can index safely
  const aliases: Record<string, Record<string, string[]>> =
    ((aliasesJSON ?? DEFAULT_ALIASES) as Record<string, Record<string, string[]>>);

  const t = text.toLowerCase();

  for (const society of Object.keys(aliases)) {
    const blocks = aliases[society] || {};
    for (const phase of Object.keys(blocks)) {
      const patterns = blocks[phase] || [];
      for (const pat of patterns) {
        if (t.includes(String(pat).toLowerCase())) {
          return { society, phase_block: phase };
        }
      }
    }
    if (t.includes(society.toLowerCase())) {
      return { society, phase_block: "" };
    }
  }
  return { society: "", phase_block: "" };
}


// ===== Regex library =====
const phoneRe       = /(?:\+?92|0)3\d{2}[\s-]?\d{7}/g;
const plotHashRe    = /(?:^|\s)#\s*([0-9]{1,6}[A-Z]?)(?=\b)/m;
const priceRe       = new RegExp(String.raw`(?:(?:demand|price|asking)\s*[:=]?\s*)?(\d{1,3}(?:[\,\.]\d{3})*(?:\.\d+)?|\d{1,4}(?:\.\d{1,2})?)\s*(cr|crore|cr\.|lac|lakh|lacs|k|m|million)?`,"gi");
const sizeWordRe    = /(\d{1,3}(?:\.\d{1,2})?)\s*(kanal|marla|sq\s?ft|sq\s?yd|gaz|yard|yds?|feet)/i;
const sizeShortRe   = /\b(\d{1,2})\s*([mk])\b/i;
const dimensionRe   = /(\d{2,3})\s*([x×*\/])\s*(\d{2,3})/i;
const plotWordRe    = /plot(?:\s*#|(?:\s*no)?|num)?\s*([\d]{1,6}[A-Z]?)/i;
const plotSeriesRe  = /\b(\d{2,4})\s*-?\s*series\b/i;
const streetRe      = /(?:street|st)\s*(\d{1,4})/i;


const flags = [
  {re:/\bndc\s*(open|clear|available)\b/i, label:"NDC open"},
  {re:/\bpossession\b/i, label:"Possession"},
  {re:/\b(sun\s*face(?:d|ing)?|south\s*open)\b/i, label:"Sun face"},
  {re:/\bcorner\b/i, label:"Corner"},
  {re:/\bpark[-\s]?facing\b/i, label:"Park facing"},
  {re:/\bboulevard|\bmain\s+boulevard|\bon\s+boulevard\b/i, label:"Boulevard"},
  {re:/\bnear\s+commercial|\bnear\s+markaz|\bback\s+open\b/i, label:"Near commercial/markaz/back open"}
];

const DIM_TO_MARLA: Record<string, number> = {"25x50":5,"30x60":7,"35x70":10,"50x90":20,"100x90":40};

function extractBarePlotNumber(text: string){
  const exclusions: Array<[number, number]> = [];
  for(const m of text.matchAll(/(?:\+?92|0)3\d{2}[\s-]?\d{7}/g)){ exclusions.push([m.index!, m.index! + m[0].length]); }
  for(const m of text.matchAll(/(\d{2,3})\s*[x×*\/]\s*(\d{2,3})/gi)){ exclusions.push([m.index!, m.index! + m[0].length]); }
  for(const m of text.matchAll(/plot(?:\s*#|(?:\s*no)?|num)?\s*([\d]{1,6}[A-Z]?)/gi)){ exclusions.push([m.index!, m.index! + m[0].length]); }
  for(const m of text.matchAll(/(?:^|\s)#\s*([0-9]{1,6}[A-Z]?)(?=\b)/gm)){ exclusions.push([m.index!, m.index! + m[0].length]); }
  for(const m of text.matchAll(/(?:(?:demand|price|asking)\s*[:=]?\s*)?(\d{1,3}(?:[\,\.]\d{3})*(?:\.\d+)?|\d{1,4}(?:\.\d{1,2})?)\s*(cr|crore|cr\.|lac|lakh|lacs|k|m|million)?/gi)){ exclusions.push([m.index!, m.index! + m[0].length]); }
  for(const m of text.matchAll(/(?:street|st)\s*\d{1,4}/gi)){ exclusions.push([m.index!, m.index! + m[0].length]); }
  const inside = (i:number)=> exclusions.some(([s,e]) => i>=s && i<e);
  for (const m of text.matchAll(/\b(\d{2,4})\b/g)){
  const i = m.index ?? 0, near = text.slice(Math.max(0,i-8), i+8).toLowerCase();
  if (inside(i)) continue;
  if (/\b(marla|kanal|sq|yard|yds?|feet|ft|street|st|series)\b/.test(near)) continue;
  return m[1];
}

  return "";
}

// ===== Price / Size / Block =====
function parsePrice(text: string){
  const matches = [...text.matchAll(priceRe)];
  if (!matches.length) return {amount:"", text:""};

  const tLower = text.toLowerCase();
  const demandIdx = tLower.indexOf("demand");
  const priceIdx  = tLower.indexOf("price");

  const plotCtxRe = /plot\s*(?:#|no|num)?\s*\d{1,6}/ig;
  function isNearPlot(i:number){
    let m; while ((m = plotCtxRe.exec(text)) !== null) {
      const start = m.index!, end = start + m[0].length;
      if ((i >= start && i <= end) || (i > end && i - end <= 8)) return true;
    } return false;
  }

  const cands: Array<{pkr:number, raw:string, score:number}> = [];
  for(const m of matches){
    const rawNum = m[1]; if(!rawNum) continue;
    const unit = (m[2]||"").toLowerCase();
    const num = parseFloat(rawNum.replace(/,/g,""));
    const idx = m.index ?? text.indexOf(m[0]);
    if (isNearPlot(idx)) continue;

    let pkr: number | undefined;
    if (["cr","cr.","crore"].includes(unit)) pkr = num * 10_000_000;
    else if (["lac","lakh","lacs"].includes(unit)) pkr = num * 100_000;
    else if (unit === "k") pkr = num * 1_000;
    else if (unit === "m" || unit === "million") pkr = num * 1_000_000;
    else {
      if (num>=1_000_000) pkr = num;
      else if (num>=0.8 && num<=10 && /cr/i.test(text)) pkr = num*10_000_000;
      else if (num>=10 && num<=500 && /(lac|lakh|lacs)/i.test(text)) pkr = num*100_000;
      else if (num>=80 && num<=500 && /demand|asking/i.test(text)) pkr = num*100_000;
    }
    if(!pkr) continue;

    let score = 0;
    if(unit) score += 3;
    if(demandIdx !== -1) score += Math.max(0, 2 - Math.abs(idx - demandIdx)/50);
    if(priceIdx  !== -1) score += Math.max(0, 1 - Math.abs(idx - priceIdx)/50);
    if(!unit && String(num).length >= 4) score -= 0.5;

    cands.push({pkr: Math.round(pkr), raw:m[0], score});
  }
  if(!cands.length) return {amount:"", text:""};
  cands.sort((a,b)=> (b.score - a.score) || (b.pkr - a.pkr));
  return {amount: cands[0].pkr, text: cands[0].raw};
}

function parseSize(text: string){
  const s1 = text.match(sizeShortRe);
  if (s1){
    const n = parseFloat(s1[1]); const u = s1[2].toLowerCase();
    return {val: n, unit: (u==="k"?"Kanal":"Marla"), dim:""};
  }
  const d = text.match(dimensionRe);
  if (d){
    const w = d[1], sep = d[2], h = d[3];
    const dimExact = `${w}${sep}${h}`;
    const dimKey   = `${w}x${h}`.toLowerCase();
    if (DIM_TO_MARLA[dimKey] !== undefined) {
      return { val: DIM_TO_MARLA[dimKey], unit: "Marla", dim: dimExact };
    }
    return { val: "", unit: dimExact, dim: dimExact };
  }
  const s2 = text.match(sizeWordRe);
  if (s2){
    const val = parseFloat(s2[1]);
    const raw = s2[2].toLowerCase().replace(/\s/g,"");
    const unitMap: Record<string, string> = {
  kanal: "Kanal",
  marla: "Marla",
  sqft: "SqFt",
  sqyd: "SqYd",
  sqyard: "SqYd",
  yard: "SqYd",
  yds: "SqYd",
  gaz: "SqYd",
  feet: "SqFt",
};

  }
  return {val:"", unit:"", dim:""};
}

// --- smarter block/phase detector ---
// Goal: prefer the token that comes *after* the word "block" (e.g., "Multi Block F" => "Block F")
//       but still handle "F Block", and numeric/roman "Phase 7" etc.
function parsePhaseBlock(text: string, style: BlockOutputStyle){
  const t = ` ${String(text || "").toLowerCase()} `;

  // small helpers
  const cap = (s: string) => s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
  const isSingleLetter = (s: string) => /^[a-z]$/i.test(s);
  const isAlphaNum = (s: string) => /^[a-z0-9-]+$/i.test(s);

  // Roman → Arabic (basic) I, II, III, IV, V, VI, VII, VIII, IX, X
  const romanToArabic = (r: string): number | null => {
    const map: Record<string, number> = {I:1,V:5,X:10,L:50,C:100,D:500,M:1000};
    const R = r.toUpperCase();
    if (!/^[IVXLCDM]+$/.test(R)) return null;
    let sum = 0;
    for (let i=0; i<R.length; i++){
      const v = map[R[i]], n = map[R[i+1]] || 0;
      sum += v < n ? -v : v;
    }
    return sum;
  };

  // 1) Strongest: token to the RIGHT of "block"
  //    Examples: "Block F", "blk G", "block executive"
  let m = t.match(/\b(?:block|blk)\s*(?!size\b)([a-z0-9-]+)\b/i);
 if (m){
   const token = m[1].trim();

    if (isSingleLetter(token)) return `Block ${token.toUpperCase()}`;
    if (/^(executive|overseas|safari|hills|extension|ext)$/i.test(token)) return cap(token);
    if (isAlphaNum(token)) return `${cap(token)} Block`;
  }

  // 2) Also support token to the LEFT of "block"
  //    Examples: "F Block", "Executive Block"
  m = t.match(/\b(?!size\b)([a-z0-9-]+)\s*(?:block|blk)\b/i);
 if (m){
   const token = m[1].trim();
    if (isSingleLetter(token)) return `Block ${token.toUpperCase()}`;
    if (/^(executive|overseas|safari|hills|extension|ext)$/i.test(token)) return cap(token);
    if (isAlphaNum(token)) return `${cap(token)} Block`;
  }

  // 3) Phases: "Phase 7", "Phase-7", "Phase VII", "7 Phase"
  m = t.match(/\bphase\s*([0-9ivxlcdm]+)\b/i) || t.match(/\b([0-9ivxlcdm]+)\s*phase\b/i);
  if (m){
    const raw = m[1].trim();
    const num = /^[0-9]+$/.test(raw) ? Number(raw) : (romanToArabic(raw) || raw);
    return `Phase ${String(num).toUpperCase()}`;
  }

  // Nothing found
  return "";
}


function parseSocietyBlockPlot(text: string, style: BlockOutputStyle, dictCSV: string, aliasesJSON?: Record<string, any> | null){
  const t = text;

  const dictHit = findSocietyFromDict(t, dictCSV);
  let society = dictHit.society || "";
  let phase_block = "";
  let plotNo = "";

  if (dictHit.block) phase_block = labelBlock(dictHit.block, style);

  if(!society){
    const hit = matchAliases(t, aliasesJSON);
    society = hit.society || "";
    if(!phase_block) phase_block = hit.phase_block || "";
  }
  if(!phase_block){
    phase_block = parsePhaseBlock(t, style);
  }

  let mSeries = t.match(plotSeriesRe);
  if (mSeries){
    plotNo = `${mSeries[1]} series`.replace(/X/g,"x");
  } else {
    let mPlot = t.match(plotWordRe);
    if (mPlot) {
      plotNo = mPlot[1];
    } else {
      const mHash = t.match(plotHashRe);
      if (mHash) plotNo = mHash[1];
    }
  }
  if (!plotNo){
    const bare = extractBarePlotNumber(t);
    if (bare) plotNo = bare;
  }
  
  return {society, phase_block, plotNo};
}

// ===== Public entry point =====
export function parseMessage(text: string, opts: ParseOptions = {}): ParsedResult{
  const style = opts.blockOutputStyle || "title";
  const dictCSV = opts.societyDictCSV || DEFAULT_SOC_DICT;

  const { society, phase_block, plotNo } = parseSocietyBlockPlot(text, style, dictCSV, opts.aliasesJSON || null);

  const phones = text.match(phoneRe) || [];
  const demand = parsePrice(text);
  const size = parseSize(text);

  const lower = text.toLowerCase();
  const notesBits: string[] = [];
  for (const f of flags){ if (f.re.test(lower)) notesBits.push(f.label); }
  if (size.dim) notesBits.push(`Dimensions ${size.dim}`);

  return {
    society,
    phase_block,
    plot_no: plotNo || "",
    size_val: (size.val as number) ?? "",
    size_unit: size.unit || "",
    demand_pkr: (demand.amount as number) ?? "",
    demand_text: demand.text || "",
    phone_e164: phones[0] ? toE164(phones[0]) : "",
    notes: Array.from(new Set(notesBits)).join(", "),
    flags: {
      corner: /\bcorner\b/i.test(lower),
      park: /park[-\s]?facing/i.test(lower),
      possession: /\bpossession\b/i.test(lower)
    },
    dimensions: size.dim || ""
  };
}
