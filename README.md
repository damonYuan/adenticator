README
====

Express middleware to authenticate and authorize the user through Active Directory and AD group.

# Usage

Initiate the Adenticator instance as below as per your requirements,
```
const Adenticator = require('Adenticator');
const adenticator = new Adenticator(
  'ldaps://example.org:8765',
  'OU=ExamplePeople,DC=UserDir,DC=UAT,DC=Example',
  ['CN=ExampleTeam,OU=Applications,DC=StaffDir,DC=UAT,DC=Example'] // note that the relationship for member groups is OR
)
```
then place it as middleware in the router,
```
this.get('/protected/resource', adenticator.login, function (req, res) {
  ...  
});
```
or use it globally for all routers in the Express app,
```
app.use(adenticator.login);
```

# TODO

- [ ] use secured LDAP client
- [ ] distinguish the AND and OR relationship in memberGroups