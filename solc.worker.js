'use strict';

// solc runs inside a Web Worker because Chrome forbids synchronous
// WebAssembly compilation on the main thread for buffers larger than 8MB.
// Workers are exempt from that limit, so importScripts + Module.cwrap work
// normally here.

let core = null;
let loadedVersion = null;

function compileStandard(inputJson, readCallback) {
  const single = function (kind, data) {
    if (kind === 'source') {
      return readCallback(Module.UTF8ToString(data));
    }
    return { error: 'SMT solver callback not supported' };
  };
  const cb = Module.addFunction(single, 'viiiii');
  try {
    return core.compileInternal(inputJson, cb, 0);
  } finally {
    Module.removeFunction(cb);
    if (core.reset) core.reset();
  }
}

self.onmessage = function (e) {
  const msg = e.data;
  if (msg.type === 'load') {
    try {
      importScripts(msg.src);
      if (typeof Module === 'undefined' || !Module.cwrap || !Module.calledRun) {
        throw new Error('solc failed to initialise in worker');
      }
      core = {
        compileInternal: Module.cwrap('solidity_compile', 'string', ['string', 'number', 'number']),
        reset: () => { if (Module._solidity_reset) Module._solidity_reset(); }
      };
      loadedVersion = msg.version;
      self.postMessage({ type: 'ready', version: msg.version });
    } catch (err) {
      self.postMessage({ type: 'error', message: String(err && err.message || err) });
    }
    return;
  }
  if (msg.type === 'compile') {
    try {
      if (!core) throw new Error('solc not loaded yet');
      const readCallback = function (path) {
        return { error: 'File import callback not supported in worker' };
      };
      const output = compileStandard(msg.input, readCallback);
      self.postMessage({ type: 'result', id: msg.id, output: output });
    } catch (err) {
      self.postMessage({ type: 'error', id: msg.id, message: String(err && err.message || err) });
    }
    return;
  }
};

self.onerror = function (err) {
  self.postMessage({ type: 'error', message: String(err && err.message || err) });
};
