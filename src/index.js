const ldap = require("ldapjs");

module.exports = Adenticator = class Adenticator {
  constructor(server, userGroup, memberGroups = []) {
    if (!server || !userGroup) throw new Error("server and group are required");
    this.server = server;
    this.userGroup = userGroup;
    this.memberGroups = memberGroups;
  }

  login = (req, res, next) => {
    let [username, password] = [null, null];
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const auth = new Buffer.from(authHeader.split(" ")[1], "base64")
        .toString()
        .split(":");
      username = auth[0];
      password = auth[1];
    }

    if (!username || !password) {
      const err = new Error("You are not authenticated!");
      res.setHeader("WWW-Authenticate", "Basic");
      err.status = 401;
      next(err);
      return;
    }

    const client = ldap.createClient({
      url: this.server,
      tlsOptions: {
        rejectUnauthorized: false,
      },
    });
    // authentication
    client.bind(`cn=${username},${this.userGroup}`, password, (err) => {
      if (err) {
        const err = new Error("Authentication failed");
        res.setHeader("WWW-Authenticate", "Basic");
        err.status = 401;
        next(err);
        return;
      }

      if (this.memberGroups.length === 0) {
        next();
        client.unbind((err) => {
          if (err) console.log("Error when unbind: ", err);
        });
        return;
      }

      // authorization
      const promises = [];
      for (let i = 0; i < this.memberGroups.length; i++) {
        promises.push(
          new Promise((resolve, reject) => {
            const memberGroup = this.memberGroups[i];
            const opts = {
              // Based on https://confluence.atlassian.com/crowdkb/active-directory-user-filter-does-not-search-nested-groups-715130424.html
              filter: `(&(CN=${username})(memberOf:1.2.840.113556.1.4.1941:=${memberGroup}))`,
              scope: "sub",
              sizeLimit: 1,
            };
            client.search(`${this.userGroup}`, opts, (err, res) => {
              if (err) {
                return reject(err);
              }

              let userEntry = null;
              res.on("searchEntry", (entry) => {
                userEntry = entry;
              });

              res.on("error", (err) => reject(err));

              res.on("end", (result) => {
                if (result.status === 0 && userEntry != null) {
                  return resolve();
                } else {
                  return reject(new Error("Not in group"));
                }
              });
            });
          })
        );
      }
      Promise.allSettled(promises).then((results) => {
        const fulfilled = results.filter((r) => r.status === "fulfilled");
        if (fulfilled.length > 0) {
          next();
          client.unbind((err) => {
            if (err) console.log("Error when unbind: ", err);
          });
          return;
        } else {
          const err = new Error("Authorization failed");
          res.setHeader("WWW-Authenticate", "Basic");
          err.status = 401;
          next(err);
          return;
        }
      });
    });
  };
};
