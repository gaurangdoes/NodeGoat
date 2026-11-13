"use strict";
// Security regression test for app/routes/contributions.js:32
// (javascript.lang.security.audit.code-string-concat): req.body values passed to eval().
const path = require("path");
const Module = require("module");

const results = { security: [], benign: [], notes: [] };
function record(kind, name, fn) {
  try {
    const ok = !!fn();
    results[kind].push({ name, passed: ok });
  } catch (e) {
    results[kind].push({ name, passed: false });
    results.notes.push(name + " error: " + (e && e.message ? e.message : String(e)));
  }
}

const repo = process.env.COBALT2_REPO || path.resolve(__dirname, "..", "..");

// --- Stub only what the sandbox lacks -------------------------------------
// Third-party modules that may not be installed (not relevant to the finding).
const fallbackStubs = {
  "bcrypt-nodejs": {
    hashSync: (p) => p, genSaltSync: () => "", compareSync: (a, b) => a === b
  },
  underscore: {}
};
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  try {
    return origLoad.apply(this, arguments);
  } catch (e) {
    if (Object.prototype.hasOwnProperty.call(fallbackStubs, request)) {
      return fallbackStubs[request];
    }
    throw e;
  }
};

// Stub the app config module (reads env files / logs); handler only uses environmentalScripts.
try {
  const configPath = require.resolve(path.join(repo, "config", "config.js"));
  const m = new Module(configPath);
  m.filename = configPath;
  m.loaded = true;
  m.exports = { environmentalScripts: [] };
  require.cache[configPath] = m;
} catch (e) {
  results.notes.push("config stub failed: " + e.message);
}

// In-memory fake Mongo db used by the real ContributionsDAO / UserDAO.
function makeDb(log) {
  return {
    collection(name) {
      return {
        update(query, doc, opts, cb) { log.updates.push({ name, query, doc }); cb(null); },
        findOne(query, cb) {
          if (name === "users") return cb(null, { userName: "alice", firstName: "A", lastName: "L" });
          return cb(null, null);
        }
      };
    }
  };
}

let ContributionsHandler = null;
try {
  ContributionsHandler = require(path.join(repo, "app", "routes", "contributions.js"));
} catch (e) {
  results.notes.push("failed to load contributions handler: " + e.message);
}

function invoke(body) {
  const log = { updates: [], renders: [], nextErr: null, thrown: null };
  const handler = new ContributionsHandler(makeDb(log));
  const req = { body, session: { userId: "1" } };
  const res = { render: (view, data) => { log.renders.push({ view, data }); } };
  try {
    handler.handleContributionsUpdate(req, res, (err) => { log.nextErr = err; });
  } catch (e) {
    log.thrown = e;
  }
  return log;
}

// --- Security assertions --------------------------------------------------
record("security", "preTax expression is not executed (no globalThis marker side effect)", () => {
  if (!ContributionsHandler) throw new Error("handler not loaded");
  delete globalThis.__cobalt2_preTax_marker;
  const log = invoke({
    preTax: "(globalThis.__cobalt2_preTax_marker = 'pwned', 5)",
    afterTax: "5",
    roth: "5"
  });
  const executed = globalThis.__cobalt2_preTax_marker === "pwned";
  delete globalThis.__cobalt2_preTax_marker;
  if (executed) results.notes.push("preTax payload was evaluated as code");
  // must not execute, and must not persist a value derived from code execution
  const persistedFive = log.updates.some((u) => u.doc && u.doc.preTax === 5);
  return !executed && !persistedFive;
});

record("security", "afterTax IIFE payload is not executed and is not stored", () => {
  if (!ContributionsHandler) throw new Error("handler not loaded");
  delete globalThis.__cobalt2_afterTax_marker;
  const log = invoke({
    preTax: "1",
    afterTax: "(function(){ globalThis.__cobalt2_afterTax_marker = 1; return 3; })()",
    roth: "1"
  });
  const executed = globalThis.__cobalt2_afterTax_marker === 1;
  delete globalThis.__cobalt2_afterTax_marker;
  const persistedThree = log.updates.some((u) => u.doc && u.doc.afterTax === 3);
  return !executed && !persistedThree;
});

record("security", "roth payload reading process state is not evaluated", () => {
  if (!ContributionsHandler) throw new Error("handler not loaded");
  delete globalThis.__cobalt2_roth_marker;
  invoke({
    preTax: "1",
    afterTax: "1",
    roth: "(globalThis.__cobalt2_roth_marker = typeof process, 2)"
  });
  const executed = globalThis.__cobalt2_roth_marker !== undefined;
  delete globalThis.__cobalt2_roth_marker;
  return !executed;
});

// --- Benign assertion -----------------------------------------------------
record("benign", "numeric contributions 10/5/5 are saved and success rendered", () => {
  if (!ContributionsHandler) throw new Error("handler not loaded");
  const log = invoke({ preTax: "10", afterTax: "5", roth: "5" });
  if (log.thrown) throw log.thrown;
  if (log.nextErr) throw log.nextErr;
  const u = log.updates.find((x) => x.name === "contributions");
  const r = log.renders[log.renders.length - 1];
  return !!u && Number(u.doc.preTax) === 10 && Number(u.doc.afterTax) === 5 &&
    Number(u.doc.roth) === 5 && !!r && r.data && r.data.updateSuccess === true;
});

record("benign", "contributions over 30% are still rejected", () => {
  if (!ContributionsHandler) throw new Error("handler not loaded");
  const log = invoke({ preTax: "20", afterTax: "10", roth: "5" });
  const r = log.renders[log.renders.length - 1];
  return log.updates.length === 0 && !!r && /cannot exceed 30/.test(r.data.updateError || "");
});

Module._load = origLoad;
results.notes.push("Handler loaded from " + repo + "/app/routes/contributions.js with in-memory db stub");
console.log("COBALT2_PROOF=" + JSON.stringify(results));
