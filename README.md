# todos-express-password

This app illustrates how to use [Passport](https://www.passportjs.org/) with
[Express](https://expressjs.com/) to sign users in with a username and password.
Use this example as a starting point for your own web applications.

## Quick Start

To run this app, clone the repository and install dependencies:

```bash
$ git clone https://github.com/passport/todos-express-password.git
$ cd todos-express-password
$ npm install
```

Then start the server.

```bash
$ npm start
```

Navigate to [`http://localhost:3000`](http://localhost:3000).

## Tutorial

Follow along with the step-by-step [Username & Password Tutorial](https://www.passportjs.org/tutorials/password/)
to learn how this app was built.

## Overview

This app illustrates how to build a todo app with sign in functionality using
Express, Passport, and the [`passport-local`](https://www.passportjs.org/packages/passport-local/)
strategy.

This app is a traditional web application, in which application logic and data
persistence resides on the server.  HTML pages and forms are rendered by the
server and client-side JavaScript is not utilized (or kept to a minimum).

This app is built using the Express web framework.  Data is persisted to a
[SQLite](https://www.sqlite.org/) database.  HTML pages are rendered using [EJS](https://ejs.co/)
templates, and are styled using vanilla CSS.

When a user first arrives at this app, they are prompted to sign in.  Once
authenticated, a login session is established and maintained between the server
and the user's browser with a cookie.

After signing in, the user can view, create, and edit todo items.  Interaction
occurs by clicking links and submitting forms, which trigger HTTP requests.
The browser automatically includes the cookie set during login with each of
these requests.

When the server receives a request, it authenticates the cookie and restores the
login session, thus authenticating the user.  It then accesses or stores records
in the database associated with the authenticated user.

## Next Steps

* Extend with credential management.

  Study [todos-express-password-credential-management](https://github.com/passport/todos-express-password-credential-management)
  to learn how to use the [Credential Managment](https://www.w3.org/TR/credential-management-1/)
  API to help the user store and select their password.

* Add social login.

  Study [todos-express-google](https://github.com/passport/todos-express-google)
  to learn how to let users sign in with their social network account, using
  their existing profile and avoiding the need to sign up and repeatedly enter
  account details.

* Add passwordless.

  Study [todos-express-webauthn](https://github.com/passport/todos-express-webauthn)
  to learn how to let users sign in with biometrics or a security key.

## License

[The Unlicense](https://opensource.org/licenses/unlicense)

## Credit

Created by [Jared Hanson](https://www.jaredhanson.me/)


## PrivacyLib GDPR decision integration

Original GDPR framework: **[PrivacyLib-REGO](https://github.com/CS-UCY-SEIT-lab/PrivacyLib-REGO)**. The PHP/JavaScript router and OPA/Rego policies bundled in `integration/privacy-lib/` come from this source repository.

This branch adds an authenticated host adapter for the PrivacyLib JavaScript router and eleven OPA/Rego policies. The runtime and policies are bundled under `integration/privacy-lib/`; no sibling checkout or evaluation CSV is required. Source provenance is recorded in that directory.

### Run and configure

Follow this application's original database/authentication setup and install its dependencies. The integration uses Node.js 22+ (also satisfy this project's existing engine constraints). Start OPA 1.x with:

```sh
opa run --server --addr 127.0.0.1:8181 integration/privacy-lib/gdpr
```

`OPA_QUERY_URL` defaults to `http://localhost:8181/v1/query`. Replace the **synthetic example metadata** in `integration/privacy-config.json` with the intended controller, purposes, retention rules and request checks. Keep credentials, application signing keys and databases outside Git.

The adapter reuses the existing host authentication. Concrete policy operations are `consent`, `lawful`, `information`, `access`, `rectification`, `erasure`, `restriction`, `portability`, `objection`, `complaint`, and `breach`, posted below `/gdpr`. `PATCH /gdpr/consent` stores the authenticated user's choice. Client-supplied subject IDs and trusted policy checks are rejected. Breach assessments require the existing host admin role or the adapter's explicit server-side allowlist.

An interactive test page is available at `/gdpr`; sign in through the original application first. Cookie/session integrations preserve or add CSRF protection on the GDPR routes.

**Scope:** the router returns decisions and proposed action plans. Except for storing consent, it does not execute profile updates, erasure, complaints, transfers, audit writes, or notifications. Access responses contain metadata; portability exports the selected stored values. This integration does not establish legal compliance or repair unrelated host authorization behavior.

Breach assessments use the server-controlled `GDPR_ADMIN_USER_IDS` allowlist, empty by default. The test fixture sets a demo user ID only inside its isolated temporary database.

### Verify independently

Install OPA 1.x and MongoDB 7's `mongod` on PATH (the SQLite host does not need MongoDB). Alternatively set `OPA_BINARY` and `MONGOD_BINARY` to their executable paths. Hosts using `mongodb-memory-server` can download a test binary or use `MONGOMS_SYSTEM_BINARY`; version 7.0.24 is the tested fixture. Python 3 is also needed where the existing integration runner is Python; set `PYTHON_BINARY` if necessary.

```sh
npm run integration:test
```

The runner starts isolated policy/application services, exercises actual authentication and user separation, and prints named checks. It uses temporary test data and does not need a running policy server on 8181. No evaluation report files or external reporting service are required.
