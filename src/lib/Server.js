'use strict';

const crypto = require('node:crypto');
const { createServer } = require('node:http');
const { stat, readFile } = require('node:fs/promises');
const { resolve, sep } = require('node:path');

const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const expressSession = require('express-session');
const debug = require('debug')('Server');

const {
  createApp,
  createError,
  createRouter,
  defineEventHandler,
  fromNodeMiddleware,
  getRouterParam,
  toNodeListener,
  readBody,
  setHeader,
  serveStatic,
} = require('h3');

const WireGuard = require('../services/WireGuard');

const {
  CHECK_UPDATE,
  PORT,
  WEBUI_HOST,
  RELEASE,
  PASSWORD,
  MAX_AGE,
  LANG,
  UI_TRAFFIC_STATS,
  UI_CHART_TYPE,
  WG_HOST,
  WG_PORT,
  WG_MTU,
  WG_DEFAULT_DNS,
  WG_PERSISTENT_KEEPALIVE,
  WG_ALLOWED_IPS,
} = require('../config');

module.exports = class Server {

  constructor() {
    const app = createApp();
    this.app = app;

    app.use(fromNodeMiddleware(expressSession({
      secret: crypto.randomBytes(256).toString('hex'),
      resave: true,
      saveUninitialized: true,
    })));

    const router = createRouter();
    app.use(router);

    router
      .get('/api/release', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return RELEASE;
      }))

      .get('/api/check-update', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return CHECK_UPDATE;
      }))

      .get('/api/lang', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${LANG}"`;
      }))

      .get('/api/remember-me', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return MAX_AGE > 0;
      }))

      .get('/api/ui-traffic-stats', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return UI_TRAFFIC_STATS;
      }))

      .get('/api/ui-chart-type', defineEventHandler((event) => {
        setHeader(event, 'Content-Type', 'application/json');
        return `"${UI_CHART_TYPE}"`;
      }))

      // Authentication
      .get('/api/session', defineEventHandler((event) => {
        const requiresPassword = !!process.env.PASSWORD;
        const authenticated = requiresPassword
          ? !!(event.node.req.session && event.node.req.session.authenticated)
          : true;

        return {
          requiresPassword,
          authenticated,
        };
      }))
      .post('/api/session', defineEventHandler(async (event) => {
        const { password, remember } = await readBody(event);

        if (typeof password !== 'string') {
          throw createError({
            status: 401,
            message: 'Missing: Password',
          });
        }

        if (password !== PASSWORD) {
          throw createError({
            status: 401,
            message: 'Incorrect Password',
          });
        }

        if (MAX_AGE && remember) {
          event.node.req.session.cookie.maxAge = MAX_AGE;
        }
        event.node.req.session.authenticated = true;
        event.node.req.session.save();

        debug(`New Session: ${event.node.req.session.id}`);

        return { succcess: true };
      }));

    // WireGuard
    app.use(
      fromNodeMiddleware((req, res, next) => {
        if (!PASSWORD || !req.url.startsWith('/api/')) {
          return next();
        }

        if (req.session && req.session.authenticated) {
          return next();
        }

        return res.status(401).json({
          error: 'Not Logged In',
        });
      }),
    );

    const router2 = createRouter();
    app.use(router2);

    router2
      .delete('/api/session', defineEventHandler((event) => {
        const sessionId = event.node.req.session.id;

        event.node.req.session.destroy();

        debug(`Deleted Session: ${sessionId}`);
        return { success: true };
      }))
      .get('/api/wireguard/client', defineEventHandler(() => {
        return WireGuard.getClients();
      }))
      .get('/api/wireguard/client/:clientId/configuration', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const client = await WireGuard.getClient({ clientId });
        const wgconfig = await WireGuard.getConfig();
        const publicKey = wgconfig.server.publicKey;
        const JC = wgconfig.server.jc;
        const JMIN = wgconfig.server.jmin;
        const JMAX = wgconfig.server.jmax;
        const S1 = wgconfig.server.s1;
        const S2 = wgconfig.server.s2;
        const H1 = wgconfig.server.h1;
        const H2 = wgconfig.server.h2;
        const H3 = wgconfig.server.h3;
        const H4 = wgconfig.server.h4;


        const clientconf = `
[Interface]\\\\n
Address = ${client.address}/32\\\\n
DNS = ${WG_DEFAULT_DNS}\\\\n
PrivateKey = ${client.privateKey}\\\\n
Jc = ${JC}\\\\n
Jmin = ${JMIN}\\\\n
Jmax = ${JMAX}\\\\n
S1 = ${S1}\\\\n
S2 = ${S2}\\\\n
H1 = ${H1}\\\\n
H2 = ${H2}\\\\n
H3 = ${H3}\\\\n
H4 = ${H4}\\\\n\\\\n
[Peer]\\\\nPublicKey = ${publicKey}\\\\n
PresharedKey = ${client.preSharedKey}\\\\n
AllowedIPs = ${WG_ALLOWED_IPS}\\\\n
Endpoint = ${WG_HOST}:${WG_PORT}\\\\n
PersistentKeepalive = ${WG_PERSISTENT_KEEPALIVE}\\\\n\\
`
        const last_config = `
{\\n
    \\"H1\\": \\"${H1}\\",\\n    
    \\"H2\\": \\"${H2}\\",\\n    
    \\"H3\\": \\"${H3}\\",\\n    
    \\"H4\\": \\"${H4}\\",\\n    
    \\"Jc\\": \\"${JC}\\",\\n    
    \\"Jmax\\": \\"${JMAX}\\",\\n    
    \\"Jmin\\": \\"${JMIN}\\",\\n    
    \\"S1\\": \\"${S1}\\",\\n    
    \\"S2\\": \\"${S2}\\",\\n    
    \\"clientId\\": \\"0\\",\\n    
    \\"client_ip\\": \\"${client.address}\\",\\n    
    \\"client_priv_key\\": \\"${client.privateKey}\\",\\n    
    \\"client_pub_key\\": \\"${client.publicKey}\\",\\n    
    \\"config\\": \\"${clientconf}",\\n    
    \\"hostName\\": \\"${WG_HOST}\\",\\n    
    \\"mtu\\": \\"${WG_MTU}\\",\\n    
    \\"port\\": ${WG_PORT},\\n    
    \\"psk_key\\": \\"${client.preSharedKey}\\",\\n    
    \\"server_pub_key\\": \\"${publicKey}\\"\\n}\\n
`;
      const jsonConf = `{
  "containers": [
      {
          "awg": {
              "H1": "${H1}",
              "H2": "${H2}",
              "H3": "${H3}",
              "H4": "${H4}",
              "Jc": "${JC}",
              "Jmax": "${JMAX}",
              "Jmin": "${JMIN}",
              "S1": "${S1}",
              "S2": "${S2}",
              "last_config": "${last_config}",
              "transport_proto": "udp"
          },
          "container": "amnezia-awg"
      }
  ],
  "defaultContainer": "amnezia-awg",
  "description": "${client.name}",
  "dns1": "1.1.1.1",
  "dns2": "1.0.0.1",
  "hostName": "${WG_HOST}"
}`;

        const compactJson = jsonConf.replace(/\s+/g, '');
        async function runPythonScript() {
          try {
            const { stdout } = await execPromise(`python3 encode.py '${compactJson}'`);
            const encodedResult = stdout.trim();
            return encodedResult;
        
          } catch (error) {
            console.error(`Error executing script: ${error}`);
          }
        }
        
        const encodedResult = await runPythonScript();

        setHeader(event, 'Content-Disposition', `attachment; filename="${client.name}.vpn"`);
        setHeader(event, 'Content-Type', 'text/plain');
        //return `vpn://${encodedResult}`;
        return encodedResult;
      }))
      .get('/api/wireguard/client/:clientId/qrcode.svg', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        const svg = await WireGuard.getClientQRCodeSVG({ clientId });
        setHeader(event, 'Content-Type', 'image/svg+xml');
        return svg;
      }))
//      .get('/api/wireguard/client/:clientId/configuration', defineEventHandler(async (event) => {
//        const clientId = getRouterParam(event, 'clientId');
//        const client = await WireGuard.getClient({ clientId });
//        const config = await WireGuard.getClientConfiguration({ clientId });
//        const configName = client.name
//          .replace(/[^a-zA-Z0-9_=+.-]/g, '-')
//          .replace(/(-{2,}|-$)/g, '-')
//          .replace(/-$/, '')
//          .substring(0, 32);
//        setHeader(event, 'Content-Disposition', `attachment; filename="${configName || clientId}.conf"`);
//        setHeader(event, 'Content-Type', 'text/plain');
//        return config;
//      }))
      .post('/api/wireguard/client', defineEventHandler(async (event) => {
        const { name } = await readBody(event);
        await WireGuard.createClient({ name });
        return { success: true };
      }))
      .delete('/api/wireguard/client/:clientId', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        await WireGuard.deleteClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/enable', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        await WireGuard.enableClient({ clientId });
        return { success: true };
      }))
      .post('/api/wireguard/client/:clientId/disable', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        await WireGuard.disableClient({ clientId });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/name', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { name } = await readBody(event);
        await WireGuard.updateClientName({ clientId, name });
        return { success: true };
      }))
      .put('/api/wireguard/client/:clientId/address', defineEventHandler(async (event) => {
        const clientId = getRouterParam(event, 'clientId');
        if (clientId === '__proto__' || clientId === 'constructor' || clientId === 'prototype') {
          throw createError({ status: 403 });
        }
        const { address } = await readBody(event);
        await WireGuard.updateClientAddress({ clientId, address });
        return { success: true };
      }));

    const safePathJoin = (base, target) => {
      // Manage web root (edge case)
      if (target === '/') {
        return `${base}${sep}`;
      }

      // Prepend './' to prevent absolute paths
      const targetPath = `.${sep}${target}`;

      // Resolve the absolute path
      const resolvedPath = resolve(base, targetPath);

      // Check if resolvedPath is a subpath of base
      if (resolvedPath.startsWith(`${base}${sep}`)) {
        return resolvedPath;
      }

      throw createError({
        status: 400,
        message: 'Bad Request',
      });
    };

    // Static assets
    const publicDir = '/app/www';
    app.use(
      defineEventHandler((event) => {
        return serveStatic(event, {
          getContents: (id) => {
            return readFile(safePathJoin(publicDir, id));
          },
          getMeta: async (id) => {
            const filePath = safePathJoin(publicDir, id);

            const stats = await stat(filePath).catch(() => {});
            if (!stats || !stats.isFile()) {
              return;
            }

            if (id.endsWith('.html')) setHeader(event, 'Content-Type', 'text/html');
            if (id.endsWith('.js')) setHeader(event, 'Content-Type', 'application/javascript');
            if (id.endsWith('.json')) setHeader(event, 'Content-Type', 'application/json');
            if (id.endsWith('.css')) setHeader(event, 'Content-Type', 'text/css');
            if (id.endsWith('.png')) setHeader(event, 'Content-Type', 'image/png');
            if (id.endsWith('.svg')) setHeader(event, 'Content-Type', 'image/svg+xml');

            return {
              size: stats.size,
              mtime: stats.mtimeMs,
            };
          },
        });
      }),
    );

    createServer(toNodeListener(app)).listen(PORT, WEBUI_HOST);
    debug(`Listening on http://${WEBUI_HOST}:${PORT}`);
  }

};
