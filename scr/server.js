const path = require('path');
const { randomUUID } = require('crypto');
const express = require('express');

const EASY_AUTH_HEADER = 'x-ms-client-principal';
const DEFAULT_ROLE_DEFINITIONS = [
  {
    id: 'r_admin',
    name: 'Admin',
    description: 'Volledige toegang tot AC-dossier',
    azureRoles: ['ac.dossiers.admin', 'Admin'],
    permissions: [
      'manage_users',
      'view_medisch',
      'edit_dossiers',
      'export_data',
      'configure_koppelingen',
      'view_dossiers',
      'open_ziekmelding',
      'view_reports',
    ],
  },
  {
    id: 'r_casemanager',
    name: 'Casemanager',
    description: 'Dossiers beheren en rapportages bekijken',
    azureRoles: ['ac.dossiers.casemanager', 'Casemanager'],
    permissions: ['view_dossiers', 'edit_dossiers', 'view_reports'],
  },
  {
    id: 'r_arts',
    name: 'Arts',
    description: 'Medische dossiers en exportrechten',
    azureRoles: ['ac.dossiers.arts', 'Arts'],
    permissions: ['view_medisch', 'edit_dossiers', 'export_data'],
  },
  {
    id: 'r_backoffice',
    name: 'Backoffice',
    description: 'Rapporteren en dossiers inzien',
    azureRoles: ['ac.dossiers.backoffice', 'Backoffice'],
    permissions: ['view_dossiers', 'export_data'],
  },
  {
    id: 'r_werkgever',
    name: 'Werkgever',
    description: 'Eigen dossiers raadplegen en ziekmeldingen doen',
    azureRoles: ['ac.dossiers.werkgever', 'Werkgever'],
    permissions: ['view_dossiers', 'open_ziekmelding'],
  },
];

const ROLE_ALIAS_OVERRIDES = safeJson(process.env.AZURE_ROLE_ALIASES);
const ROLE_DEFINITIONS = DEFAULT_ROLE_DEFINITIONS.map((role) => {
  const overrides = ROLE_ALIAS_OVERRIDES?.[role.id];
  const merged = overrides && Array.isArray(overrides) ? overrides : role.azureRoles;
  return {
    ...role,
    azureRoles: Array.from(new Set(merged.filter(Boolean))),
  };
});

const LOCAL_AUTH_BYPASS = process.env.LOCAL_AUTH_BYPASS === '1';
const LOCAL_AUTH_ROLES = (process.env.LOCAL_AUTH_ROLES || 'ac.dossiers.admin')
  .split(',')
  .map((role) => role.trim())
  .filter(Boolean);
let devBypassLogged = false;

function safeJson(value) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch (error) {
    console.warn('Kon JSON-configuratie niet parsen:', error.message);
    return null;
  }
}

function unique(values) {
  return Array.from(new Set(values));
}

function decodeClientPrincipal(headerValue) {
  if (!headerValue) return null;
  try {
    const decoded = Buffer.from(headerValue, 'base64').toString('utf8');
    return JSON.parse(decoded);
  } catch (error) {
    console.warn('Kon x-ms-client-principal niet decoderen:', error.message);
    return null;
  }
}

function collectClaims(principal) {
  const list = Array.isArray(principal?.claims) ? principal.claims : [];
  return list.map((claim) => ({
    type: String(claim?.typ || '').toLowerCase(),
    value: claim?.val,
  }));
}

function claimsToMap(claims) {
  return claims.reduce((acc, claim) => {
    if (!claim.type) return acc;
    if (acc[claim.type] === undefined) {
      acc[claim.type] = claim.value;
    } else if (Array.isArray(acc[claim.type])) {
      acc[claim.type].push(claim.value);
    } else {
      acc[claim.type] = [acc[claim.type], claim.value];
    }
    return acc;
  }, {});
}

function deriveRoles(principal, claims) {
  const roleClaimType =
    String(principal?.role_typ || principal?.roleClaimType || 'roles').toLowerCase();
  const roles = new Set(
    (principal?.userRoles || []).filter((role) => role && role.toLowerCase() !== 'anonymous')
  );

  claims
    .filter((claim) => claim.type === 'roles' || claim.type === roleClaimType)
    .forEach((claim) => {
      if (claim.value && claim.value.toLowerCase() !== 'anonymous') {
        roles.add(claim.value);
      }
    });

  return Array.from(roles);
}

function buildDevPrincipal() {
  if (!LOCAL_AUTH_BYPASS) {
    return null;
  }

  if (process.env.LOCAL_AUTH_PRINCIPAL) {
    const parsed = safeJson(process.env.LOCAL_AUTH_PRINCIPAL);
    if (parsed) return parsed;
  }

  const roles = LOCAL_AUTH_ROLES.length ? LOCAL_AUTH_ROLES : ['ac.dossiers.admin'];
  return {
    identityProvider: 'local-dev',
    userId: 'local-dev',
    userDetails: 'Local Developer',
    userRoles: roles,
    claims: [
      { typ: 'name', val: 'Local Developer' },
      { typ: 'preferred_username', val: 'local@example.com' },
      ...roles.map((role) => ({ typ: 'roles', val: role })),
    ],
  };
}

function buildAuthState(principal) {
  const claimsList = collectClaims(principal);
  const claimsMap = claimsToMap(claimsList);
  const roleNames = deriveRoles(principal, claimsList);
  const matchedRoles = ROLE_DEFINITIONS.filter((definition) =>
    definition.azureRoles.some((azureRole) => roleNames.includes(azureRole))
  );
  const permissions = unique(matchedRoles.flatMap((role) => role.permissions)).sort();
  const primaryEmail = Array.isArray(claimsMap.emails) ? claimsMap.emails[0] : claimsMap.emails;

  const user = {
    id:
      claimsMap['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] ||
      claimsMap.oid ||
      principal?.userId ||
      null,
    name:
      claimsMap.name ||
      claimsMap['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'] ||
      principal?.userDetails ||
      null,
    email: primaryEmail || claimsMap.preferred_username || null,
    provider: principal?.identityProvider || null,
  };

  return {
    isAuthenticated: true,
    user,
    roles: roleNames,
    resolvedRoles: matchedRoles.map((role) => ({
      id: role.id,
      name: role.name,
      description: role.description,
    })),
    permissions,
    principal,
    claims: claimsMap,
  };
}

function authContextMiddleware(req, res, next) {
  const header = req.headers[EASY_AUTH_HEADER];
  let principal = header ? decodeClientPrincipal(header) : null;

  if (!principal && LOCAL_AUTH_BYPASS) {
    principal = buildDevPrincipal();
    if (principal && !devBypassLogged) {
      console.warn(
        'LOCAL_AUTH_BYPASS is actief. Gebruik dit alleen voor lokaal testen; in productie wordt de Azure AD header verwacht.'
      );
      devBypassLogged = true;
    }
  }

  if (!principal) {
    req.auth = {
      isAuthenticated: false,
      user: null,
      roles: [],
      resolvedRoles: [],
      permissions: [],
      claims: {},
    };
    return next();
  }

  req.auth = buildAuthState(principal);
  return next();
}

function requireAuth(req, res, next) {
  if (req.auth?.isAuthenticated) {
    return next();
  }
  return res.status(401).json({
    ok: false,
    error: 'Niet aangemeld bij Azure AD.',
  });
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.auth?.isAuthenticated) {
      return res.status(401).json({
        ok: false,
        error: 'Niet aangemeld bij Azure AD.',
      });
    }
    if (!req.auth.permissions.includes(permission)) {
      return res.status(403).json({
        ok: false,
        error: `Geen toegang. Vereiste Azure AD-rol voor ${permission}.`,
      });
    }
    return next();
  };
}
const AI_ACTIVITY_DEFINITIONS = [
  {
    id: 'audiometrie',
    label: 'Audiometrie',
    keywords: ['audiometrie', 'audiogram', 'gehoortest', 'gehoor test', 'geluidstest'],
  },
  {
    id: 'bloed',
    label: 'Bloedonderzoek',
    keywords: ['bloedonderzoek', 'bloed analyse', 'bloedafname', 'labtest', 'laboratorium'],
  },
  {
    id: 'ecg',
    label: 'ECG',
    keywords: ['ecg', 'hartfilmpje', 'cardiogram', 'elektrocardiogram'],
  },
  {
    id: 'spiro',
    label: 'Spirometrie',
    keywords: ['spirometrie', 'spiro', 'longfunctie', 'long functie', 'longonderzoek'],
  },
  {
    id: 'urine',
    label: 'Urine (dipstick)',
    keywords: ['urine', 'dipstick', 'urinetest', 'urine onderzoek'],
  },
  {
    id: 'visus',
    label: 'Visus',
    keywords: ['visus', 'oogtest', 'zichttest', 'zichtmeting'],
  },
  {
    id: 'ergo',
    label: 'Ergometrie',
    keywords: ['ergometrie', 'fietstest', 'inspanningstest', 'belastingstest'],
  },
  {
    id: 'narcotica',
    label: 'Narcotica (urine)',
    keywords: ['narcotica', 'drugstest', 'drugs test', 'middelen controle'],
  },
  {
    id: 'vaccinatie',
    label: 'Vaccinatie (indien nodig)',
    keywords: ['vaccin', 'vaccinatie', 'inenting'],
  },
  {
    id: 'hb',
    label: 'Hb (vingerprik)',
    keywords: ['hb', 'hemoglobine', 'vingerprik'],
  },
  {
    id: 'glucose',
    label: 'Glucose',
    keywords: ['glucose', 'suiker', 'bloedsuiker'],
  },
  {
    id: 'cholesterol',
    label: 'Cholesterol',
    keywords: ['cholesterol'],
  },
  {
    id: 'bmi',
    label: 'BMI / lengte / gewicht',
    keywords: ['bmi', 'lengte', 'gewicht', 'body mass', 'bodymass'],
  },
  {
    id: 'bloeddruk',
    label: 'Bloeddruk',
    keywords: ['bloeddruk', 'hypertensie', 'bloed druk'],
  },
  {
    id: 'gehoor',
    label: 'Gehoor (screening)',
    keywords: ['gehoor', 'gehoorscreening', 'gehoor test', 'luistertest'],
  },
  {
    id: 'oog',
    label: 'Oog / kleurenzien',
    keywords: ['kleurenzien', 'kleur test', 'oogonderzoek', 'ishihara'],
  },
];

const AI_ROLE_DEFINITIONS = [
  {
    role: 'Monteur mechaniek',
    keywords: ['monteur mechaniek', 'monteur', 'mechaniek', 'monteur techniek'],
  },
  {
    role: 'Vrachtwagenchauffeur',
    keywords: ['vrachtwagenchauffeur', 'chauffeur', 'truck', 'vrachtwagen'],
  },
  {
    role: 'Laborant',
    keywords: ['laborant', 'laboratorium', 'labmedewerker', 'analist'],
  },
];

function normaliseString(value) {
  if (value === undefined || value === null) {
    return '';
  }
  return String(value).trim();
}

function lower(value) {
  return normaliseString(value).toLowerCase();
}

function findActivityDefinition(value) {
  const text = lower(value);
  if (!text) {
    return null;
  }

  for (const def of AI_ACTIVITY_DEFINITIONS) {
    if (text === def.id || text === def.label.toLowerCase()) {
      return def;
    }
    if (def.keywords.some((keyword) => keyword && text.includes(keyword))) {
      return def;
    }
  }

  return null;
}

function normaliseRole(value) {
  const text = lower(value);
  if (!text) {
    return null;
  }

  for (const def of AI_ROLE_DEFINITIONS) {
    if (text === def.role.toLowerCase()) {
      return def.role;
    }
    if (def.keywords.some((keyword) => keyword && text.includes(keyword))) {
      return def.role;
    }
  }

  return normaliseString(value) || null;
}

function detectActivitiesInText(text) {
  const lowerText = lower(text);
  const matches = new Map();

  for (const def of AI_ACTIVITY_DEFINITIONS) {
    const allKeywords = new Set([
      def.id,
      def.label.toLowerCase(),
      ...def.keywords.map((keyword) => keyword.toLowerCase()),
    ]);

    for (const keyword of allKeywords) {
      if (!keyword) continue;
      if (lowerText.includes(keyword)) {
        if (!matches.has(def.id)) {
          matches.set(def.id, {
            id: def.id,
            label: def.label,
            source: 'ai',
            reason: `Herkenning van "${keyword}" in tekst.`,
          });
        }
        break;
      }
    }
  }

  return matches;
}

function gatherStrings(node, acc = [], depth = 0, limit = 2000) {
  if (acc.length >= limit || depth > 8) {
    return acc;
  }

  if (typeof node === 'string') {
    acc.push(node);
    return acc;
  }

  if (Array.isArray(node)) {
    for (const value of node) {
      if (acc.length >= limit) break;
      gatherStrings(value, acc, depth + 1, limit);
    }
    return acc;
  }

  if (node && typeof node === 'object') {
    for (const value of Object.values(node)) {
      if (acc.length >= limit) break;
      gatherStrings(value, acc, depth + 1, limit);
    }
  }

  return acc;
}

function findFirstByKeys(node, keys, depth = 0) {
  if (!node || depth > 6) {
    return null;
  }

  if (typeof node === 'string') {
    return node;
  }

  if (Array.isArray(node)) {
    for (const item of node) {
      const result = findFirstByKeys(item, keys, depth + 1);
      if (result) return result;
    }
    return null;
  }

  if (typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      const lowerKey = key.toLowerCase();
      if (keys.includes(lowerKey)) {
        const result = findFirstByKeys(value, keys, depth + 1);
        if (result) return result;
      }
    }

    for (const value of Object.values(node)) {
      const result = findFirstByKeys(value, keys, depth + 1);
      if (result) return result;
    }
  }

  return null;
}

function findFirstObjectByKeys(node, keys, depth = 0) {
  if (!node || depth > 6) {
    return null;
  }

  if (Array.isArray(node)) {
    for (const item of node) {
      const found = findFirstObjectByKeys(item, keys, depth + 1);
      if (found) return found;
    }
    return null;
  }

  if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      if (keys.includes(key.toLowerCase()) && value && typeof value === 'object') {
        return value;
      }
    }

    for (const value of Object.values(node)) {
      const found = findFirstObjectByKeys(value, keys, depth + 1);
      if (found) return found;
    }
  }

  return null;
}

function detectRoleInText(text) {
  const lowerText = lower(text);
  for (const def of AI_ROLE_DEFINITIONS) {
    if (def.keywords.some((keyword) => lowerText.includes(keyword))) {
      return def.role;
    }
    if (lowerText.includes(def.role.toLowerCase())) {
      return def.role;
    }
  }
  return null;
}

function detectBsn(text) {
  const matches = String(text)
    .match(/\b\d{8,9}\b/g);
  if (!matches || !matches.length) {
    return null;
  }
  return matches.find((candidate) => candidate.length === 9) || matches[0] || null;
}

function detectNameInText(text) {
  const match = String(text).match(
    /(?:naam|werknemer|medewerker)\s*[:\-]\s*([A-Za-zÀ-ÿ'\s\.-]{3,})/i
  );
  if (match) {
    return normaliseString(match[1]);
  }
  return null;
}

function detectNoteInText(text) {
  const match = String(text).match(
    /(?:notitie|advies|opmerking|toelichting)\s*[:\-]\s*([^\n]+)/i
  );
  if (match) {
    return normaliseString(match[1]);
  }
  return null;
}

function analyseUploadPayload(filename, content) {
  const raw = normaliseString(content);
  const agent = {
    filename: filename || 'upload',
    activities: [],
    warnings: [],
  };

  if (!raw) {
    agent.warnings.push('Bestand bevat geen tekst.');
    agent.summary = 'Geen analyse uitgevoerd: leeg bestand.';
    return agent;
  }

  let json = null;
  if (raw.startsWith('{') || raw.startsWith('[')) {
    try {
      json = JSON.parse(raw);
    } catch (error) {
      agent.warnings.push('Kon het bestand niet als JSON interpreteren. Tekstuele analyse uitgevoerd.');
    }
  }

  const activityMatches = new Map();

  if (json) {
    const interestingKeys = ['activ', 'onderzoek', 'test', 'voorstel', 'keuring'];
    const targetedStrings = [];

    function gatherTargeted(node, depth = 0) {
      if (depth > 6) return;
      if (typeof node === 'string') {
        targetedStrings.push(node);
        return;
      }
      if (Array.isArray(node)) {
        for (const value of node) {
          gatherTargeted(value, depth + 1);
        }
        return;
      }
      if (node && typeof node === 'object') {
        for (const [key, value] of Object.entries(node)) {
          if (interestingKeys.some((part) => key.toLowerCase().includes(part))) {
            gatherTargeted(value, depth + 1);
          }
        }
      }
    }

    gatherTargeted(json);
    const allStrings = targetedStrings.length
      ? targetedStrings
      : gatherStrings(json);

    for (const candidate of allStrings) {
      const def = findActivityDefinition(candidate);
      if (def && !activityMatches.has(def.id)) {
        activityMatches.set(def.id, {
          id: def.id,
          label: def.label,
          source: 'ai',
          reason: `Gevonden in upload (${normaliseString(candidate).slice(0, 80)}).`,
        });
      }
    }
  }

  const textMatches = detectActivitiesInText(raw);
  for (const [id, hit] of textMatches.entries()) {
    if (!activityMatches.has(id)) {
      activityMatches.set(id, hit);
    }
  }

  const activities = Array.from(activityMatches.values()).sort((a, b) =>
    a.label.localeCompare(b.label, 'nl')
  );

  agent.activities = activities;

  const jsonNote = json
    ? findFirstByKeys(json, ['note', 'notes', 'notitie', 'opmerking', 'advies', 'toelichting'])
    : null;
  const textNote = detectNoteInText(raw);
  const note = normaliseString(jsonNote || textNote);
  if (note) {
    agent.note = note;
  }

  let employee = null;
  if (json) {
    const employeeNode = findFirstObjectByKeys(json, [
      'employee',
      'werknemer',
      'medewerker',
      'client',
      'persoon',
    ]);
    if (employeeNode) {
      employee = {
        name: normaliseString(
          findFirstByKeys(employeeNode, ['name', 'naam', 'fullname'])
        ) || null,
        bsn:
          normaliseString(
            findFirstByKeys(employeeNode, ['bsn', 'identificatie', 'identifier', 'id'])
          ) || null,
        role:
          normaliseRole(
            findFirstByKeys(employeeNode, ['functie', 'role', 'functieNaam', 'job'])
          ) || null,
      };
    }
  }

  const textRole = detectRoleInText(raw);
  const textBsn = detectBsn(raw);
  const textName = detectNameInText(raw);

  if (!employee && (textRole || textBsn || textName)) {
    employee = { name: textName || null, bsn: textBsn || null, role: textRole || null };
  } else if (employee) {
    employee.name = employee.name || textName || null;
    employee.bsn = employee.bsn || textBsn || null;
    employee.role = employee.role || textRole || null;
  }

  if (employee) {
    const cleaned = {
      name: employee.name || null,
      bsn: employee.bsn || null,
      role: employee.role ? normaliseRole(employee.role) : null,
    };
    if (cleaned.name || cleaned.bsn || cleaned.role) {
      agent.employee = cleaned;
    }
  }

  if (!activities.length) {
    agent.warnings.push('Geen herkenbare activiteiten aangetroffen.');
  }

  const summaryParts = [];
  if (activities.length) {
    summaryParts.push(
      `Herkende activiteiten: ${activities
        .map((item) => item.label)
        .join(', ')}.`
    );
  } else {
    summaryParts.push('Geen activiteiten herkend.');
  }

  if (agent.employee?.role) {
    summaryParts.push(`Gedetecteerde functie: ${agent.employee.role}.`);
  }
  if (agent.employee?.bsn) {
    summaryParts.push(`BSN uit bestand: ${agent.employee.bsn}.`);
  }
  if (agent.note) {
    summaryParts.push('Notitie uit bestand toegevoegd.');
  }
  if (agent.warnings.length) {
    summaryParts.push(`Waarschuwing: ${agent.warnings.join(' ')}`);
  }

  agent.summary = summaryParts.join(' ');

  return agent;
}

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(authContextMiddleware);

app.get('/api/auth/me', requireAuth, (req, res) => {
  const payload = {
    ok: true,
    user: req.auth.user,
    roles: req.auth.roles,
    resolvedRoles: req.auth.resolvedRoles,
    permissions: req.auth.permissions,
    roleMatrix: ROLE_DEFINITIONS.map((role) => ({
      id: role.id,
      name: role.name,
      description: role.description,
      permissions: role.permissions,
    })),
  };
  return res.status(200).json(payload);
});

app.post('/api/ai/keuringsvoorstel/analyse', requirePermission('view_dossiers'), (req, res) => {
  const { filename = 'upload', content } = req.body || {};

  if (typeof content !== 'string') {
    return res.status(400).json({
      ok: false,
      error: 'Ongeldig verzoek. Stuur de tekstinhoud van het bestand mee.',
    });
  }

  try {
    const agent = analyseUploadPayload(filename, content);
    return res.status(200).json({ ok: true, agent });
  } catch (error) {
    console.error('Failed to analyse upload payload:', error);
    return res.status(500).json({
      ok: false,
      error: 'Analyseren van het bestand is mislukt.',
    });
  }
});



const staticDir = path.join(__dirname, '..', 'public');
app.use(express.static(staticDir));

app.get('/logout', (req, res) => {
  const queryStart = req.originalUrl.indexOf('?');
  const suffix = queryStart >= 0 ? req.originalUrl.slice(queryStart) : '';
  const location = `/.auth/logout${suffix}`;

  return res.redirect(location);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

const port = Number(process.env.PORT) || 3000;
let server = null;

if (require.main === module) {
  server = app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
  });
}


module.exports = app;
module.exports.server = server;

