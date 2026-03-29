const { app, initRuntime } = require("../src/app");

let readyPromise = null;

module.exports = async (req, res) => {
  if (!readyPromise) {
    readyPromise = initRuntime();
  }

  await readyPromise;
  return app(req, res);
};
