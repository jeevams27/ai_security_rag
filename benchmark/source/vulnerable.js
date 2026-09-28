// Benchmark module: intentionally vulnerable JavaScript code + safe code.

const { execFile } = require("child_process");

/** VULNERABLE (CMD-001): user input interpolated into a shell command. */
function pingHostVulnerable(db, host) {
  const cmd = "ping -c 1 " + host;
  require("child_process").exec(cmd, (err, stdout) => {
    if (err) throw err;
    console.log(stdout);
  });
}

/** SAFE (CMD-001): execFile with argument array, no shell interpolation. */
function pingHostSafe(host) {
  execFile("ping", ["-c", "1", host], (err, stdout) => {
    if (err) throw err;
    console.log(stdout);
  });
}

/** VULNERABLE (SQL-001): user id concatenated directly into SQL. */
function searchProductsVulnerable(db, term) {
  const query = "SELECT * FROM products WHERE name LIKE '%" + term + "%'";
  return db.query(query);
}

/** SAFE (SQL-001): parameterized query. */
function searchProductsSafe(db, term) {
  return db.query("SELECT * FROM products WHERE name LIKE ?", [`%${term}%`]);
}

module.exports = {
  pingHostVulnerable,
  pingHostSafe,
  searchProductsVulnerable,
  searchProductsSafe,
};
