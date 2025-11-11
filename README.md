# AC-dossier Server

This project exposes a lightweight Express server that powers the AC-dossier
front-end. The service is responsible for hosting the static assets that make
up the user interface, handling authentication redirects, and providing the AI
analysis endpoint used by the application.

## Responsibilities

- **Static site hosting** – Serves the contents of the `public/` directory,
  including `index.html`, so the client can be delivered without an additional
  web server.
- **Authentication redirect** – Implements `GET /logout`, which forwards users
  to the underlying authentication provider via `/.auth/logout` while
  preserving any provided query parameters.
- **AI dossier analysis** – Exposes `POST /api/ai/keuringsvoorstel/analyse`, an
  endpoint that inspects uploaded dossier content to detect relevant
  activities, employee data, and notes. The endpoint expects JSON with a
  textual `content` field (and an optional `filename`) and returns a structured
  summary.

## Prerequisites

- Node.js 18 or newer
- NPM 9 or newer

## Installation

```bash
npm install
```

## Running the server

```bash
npm start
```

By default the server listens on port `3000`. You can override this by setting
the `PORT` environment variable before starting the application.

## Authentication & RBAC

The server relies on Azure App Service Authentication (a.k.a. Easy Auth) to
populate the `X-MS-CLIENT-PRINCIPAL` header. The middleware decodes this header,
maps Azure AD app roles to in-app permissions, and exposes the context through:

- `GET /api/auth/me` – returns the signed-in user information, granted roles,
  and the static RBAC matrix so the front-end can render the read-only overview.
- Protected APIs such as `POST /api/ai/keuringsvoorstel/analyse` – require the
  `view_dossiers` permission, enforced via the Azure AD role mapping.

### Configuring roles

| Role ID        | Azure AD app-role value(s)                     | Permissions                                                        |
| -------------- | ---------------------------------------------- | ------------------------------------------------------------------ |
| `r_admin`      | `ac.dossiers.admin`, `Admin`                   | All permissions                                                    |
| `r_casemanager`| `ac.dossiers.casemanager`, `Casemanager`       | `view_dossiers`, `edit_dossiers`, `view_reports`                   |
| `r_arts`       | `ac.dossiers.arts`, `Arts`                     | `view_medisch`, `edit_dossiers`, `export_data`                     |
| `r_backoffice` | `ac.dossiers.backoffice`, `Backoffice`         | `view_dossiers`, `export_data`                                     |
| `r_werkgever`  | `ac.dossiers.werkgever`, `Werkgever`           | `view_dossiers`, `open_ziekmelding`                                |

Override the Azure AD role names per definition by setting
`AZURE_ROLE_ALIASES` to a JSON object, for example:

```bash
export AZURE_ROLE_ALIASES='{"r_admin":["Prod.Admin"],"r_werkgever":["Customer.Read"]}'
```

### Local development

When running outside Azure you can enable a deterministic fake principal:

```bash
export LOCAL_AUTH_BYPASS=1
export LOCAL_AUTH_ROLES="ac.dossiers.admin"
npm start
```

Optional: provide a full JSON payload via `LOCAL_AUTH_PRINCIPAL` to mimic a
specific Azure AD claim set.

### DAB hardening

`infra/dab/dab-config.json` now grants read-only access to any authenticated
caller and restricts write operations to the `ac.dossiers.admin` role, ensuring
the data API builder aligns with the same Azure AD permissions.
