const config = require("../config");

function getRepository() {
  if (config.dbClient === "postgres") {
    return require("./postgresCveRepository");
  }

  return require("./sqliteCveRepository");
}

module.exports = getRepository();
