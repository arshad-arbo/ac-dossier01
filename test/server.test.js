const request = require('supertest');

const buildPrincipalHeader = (roles = ['ac.dossiers.admin']) => {
  const payload = {
    identityProvider: 'aad',
    userId: 'test-user',
    userDetails: 'Unit Test',
    userRoles: roles,
    claims: [
      { typ: 'name', val: 'Unit Test' },
      { typ: 'preferred_username', val: 'unit@example.com' },
      ...roles.map((role) => ({ typ: 'roles', val: role })),
    ],
  };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
};

const loadApp = (options = {}) => {
  jest.resetModules();
  if (typeof options.devBypass === 'boolean') {
    process.env.LOCAL_AUTH_BYPASS = options.devBypass ? '1' : '0';
  } else if (!process.env.LOCAL_AUTH_BYPASS) {
    process.env.LOCAL_AUTH_BYPASS = '1';
  }
  process.env.LOCAL_AUTH_ROLES = Array.isArray(options.devRoles)
    ? options.devRoles.join(',')
    : options.devRoles || process.env.LOCAL_AUTH_ROLES || 'ac.dossiers.admin';
  return require('../src/server');
};

describe('server routes', () => {
  let app;

  beforeEach(() => {
    app = loadApp({ devBypass: true });
  });

  describe('GET /', () => {
    it('serves the index page', async () => {
      const response = await request(app).get('/');

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toMatch(/html/);
      expect(response.text.toLowerCase()).toContain('<!doctype html>');
    });
  });

  describe('GET /logout', () => {
    it('redirects to the platform logout endpoint', async () => {
      const response = await request(app).get('/logout');

      expect(response.status).toBe(302);
      expect(response.headers.location).toBe('/.auth/logout');
    });

    it('preserves query parameters when redirecting', async () => {
      const response = await request(app).get(
        '/logout?id_token_hint=token&post_logout_redirect_uri=%2Fgoodbye&state=abc'
      );

      expect(response.status).toBe(302);
      expect(response.headers.location).toBe(
        '/.auth/logout?id_token_hint=token&post_logout_redirect_uri=%2Fgoodbye&state=abc'
      );
    });
  });

  describe('POST /api/ai/keuringsvoorstel/analyse', () => {
    it('returns an error when the payload is missing content', async () => {
      const response = await request(app)
        .post('/api/ai/keuringsvoorstel/analyse')
        .send({})
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(400);
      expect(response.body).toEqual(
        expect.objectContaining({
          ok: false,
          error: expect.stringContaining('Ongeldig verzoek'),
        })
      );
    });

    it('analyses valid AI payloads', async () => {
      const response = await request(app)
        .post('/api/ai/keuringsvoorstel/analyse')
        .send({
          filename: 'test.json',
          content: JSON.stringify({
            werknemer: { naam: 'Jan Jansen', functie: 'Monteur' },
            activiteiten: ['Bloedonderzoek'],
          }),
        })
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(
        expect.objectContaining({
          ok: true,
          agent: expect.objectContaining({
            filename: 'test.json',
            activities: expect.any(Array),
            summary: expect.any(String),
          }),
        })
      );
    });

    it('requires authentication when dev bypass is disabled', async () => {
      app = loadApp({ devBypass: false });
      const response = await request(app)
        .post('/api/ai/keuringsvoorstel/analyse')
        .send({ content: 'test' })
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(401);
      expect(response.body).toEqual(
        expect.objectContaining({
          ok: false,
        })
      );
    });

    it('rejects callers without the necessary Azure AD role', async () => {
      app = loadApp({ devBypass: false });
      const response = await request(app)
        .post('/api/ai/keuringsvoorstel/analyse')
        .set('x-ms-client-principal', buildPrincipalHeader(['ac.dossiers.werkgever']))
        .send({ content: 'test' })
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(403);
    });

    it('accepts valid Azure AD callers when roles contain view permission', async () => {
      app = loadApp({ devBypass: false });
      const response = await request(app)
        .post('/api/ai/keuringsvoorstel/analyse')
        .set('x-ms-client-principal', buildPrincipalHeader(['ac.dossiers.casemanager']))
        .send({
          filename: 'azure.json',
          content: JSON.stringify({ werknemer: { naam: 'Azure', functie: 'Casemanager' } }),
        })
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
    });
  });

  describe('GET /api/auth/me', () => {
    it('returns the auth context when dev bypass is enabled', async () => {
      const response = await request(app).get('/api/auth/me');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(
        expect.objectContaining({
          ok: true,
          user: expect.any(Object),
          roleMatrix: expect.any(Array),
        })
      );
    });

    it('requires Azure AD when dev bypass is disabled', async () => {
      app = loadApp({ devBypass: false });
      const response = await request(app).get('/api/auth/me');

      expect(response.status).toBe(401);
    });
  });
});

