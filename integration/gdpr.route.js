'use strict';
const express = require('express');
const db = require('../db');
const Joi = require('joi');
const { randomUUID } = require('node:crypto');
const { GdprRouter } = require('./privacy-lib/gdpr-router.cjs');
const config = require('./privacy-config.json');
const auth = () => (req, res, next) => req.user ? next() : res.status(401).json({ error: 'Please sign in' });
const catchAsync = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const ApiError = require('http-errors');

const gdpr = new GdprRouter();
const router = express.Router();
const ready = new Promise((resolve, reject) => db.run(
  'CREATE TABLE IF NOT EXISTS privacy_consents (user_id INTEGER PRIMARY KEY, value TEXT NOT NULL, withdrawn INTEGER NOT NULL)',
  error => error ? reject(error) : resolve()));
const get = (sql, args) => new Promise((resolve, reject) => db.get(sql, args, (error, row) => error ? reject(error) : resolve(row)));
const all = (sql, args) => new Promise((resolve, reject) => db.all(sql, args, (error, rows) => error ? reject(error) : resolve(rows)));
const run = (sql, args) => new Promise((resolve, reject) => db.run(sql, args, error => error ? reject(error) : resolve()));
const fields = Joi.array().items(Joi.string().valid('username', 'todos')).min(1).unique();
const requestId = Joi.string().max(128);
const schemas = {
  consent: Joi.object({}),
  lawful: Joi.object({}),
  information: Joi.object({}),
  access: Joi.object({}),
  rectification: Joi.object({ request_id: requestId, updates: Joi.object({
    username: Joi.string().min(1).max(200),
  }).min(1).required() }),
  erasure: Joi.object({ request_id: requestId, reason: Joi.string().max(100), fields }),
  restriction: Joi.object({ request_id: requestId, reason: Joi.string().max(100), fields }),
  portability: Joi.object({ request_id: requestId, transfer_requested: Joi.boolean(),
    transfer_service_id: Joi.string().max(100) }),
  objection: Joi.object({ request_id: requestId, reason: Joi.string().max(100), fields }),
  complaint: Joi.object({ request_id: requestId, authority_id: Joi.string().max(100).required(),
    description: Joi.string().min(1).max(2000).required() }),
  breach: Joi.object({ incident_id: Joi.string().max(128).required(),
    detected: Joi.boolean(), hours_since_detected: Joi.number().min(0),
    risks: Joi.array().items(Joi.string().valid('rights_freedoms', 'identity_theft',
      'discrimination', 'financial_loss', 'reputational_damage', 'minor')).min(1),
    summary: Joi.string().max(2000) }),
};
function validate(schema, body) {
  const result = schema.unknown(false).validate(body === undefined ? {} : body,
    { convert: false, abortEarly: false });
  if (result.error) throw new ApiError(400, result.error.details.map(item => item.message).join('; '));
  return result.value;
}
router.get('/', auth(), (req, res) => res.render('gdpr', { user: req.user }));
router.patch('/consent', auth(), catchAsync(async (req, res) => {
  const value = validate(Joi.object({
    value: Joi.string().valid('yes', 'no').required(), withdrawn: Joi.boolean().required(),
  }), req.body);
  await ready;
  await run('INSERT INTO privacy_consents(user_id,value,withdrawn) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET value=excluded.value,withdrawn=excluded.withdrawn',
    [req.user.id, value.value, value.withdrawn ? 1 : 0]);
  res.json(value);
}));
router.post('/:policy', auth(), catchAsync(async (req, res) => {
  const policy = req.params.policy;
  if (!Object.hasOwn(schemas, policy)) throw new ApiError(400, 'Unknown GDPR operation');
  // Incident assessment is an administrative operation, not a user self-service right.
  if (policy === 'breach' && !(process.env.GDPR_ADMIN_USER_IDS || '').split(',').map(id => id.trim()).includes(String(req.user.id))) throw new ApiError(403, 'Administrator access required');
  const value = validate(schemas[policy], req.body);
  const userId = String(req.user.id);
  await ready;
  const consent = await get('SELECT value,withdrawn FROM privacy_consents WHERE user_id=?', [req.user.id]);
  const todos = await all('SELECT title,completed FROM todos WHERE owner_id=? ORDER BY id', [req.user.id]);
  const input = {
    controller: config.controller, dpo: config.dpo, storage: config.storage,
    lawful_purposes: config.lawful_purposes, third_parties: config.third_parties,
    services: config.services, exceptions: config.exceptions,
    supervisory_authorities: config.supervisory_authorities,
    consents: consent ? { [userId]: { value: consent.value, withdrawn: Boolean(consent.withdrawn) } } : {},
    users: [{ id: userId, data_items: ['username', 'todos'].map(field => ({
      field, value: field === 'username' ? req.user.username : JSON.stringify(todos), purpose: 'contract', source: 'user', purpose_presented: true,
    })) }],
    request: {},
  };
  if (policy === 'access') input.request.access = { user_id: userId };
  if (['rectification', 'erasure', 'restriction', 'portability', 'objection', 'complaint'].includes(policy)) {
    input.request[policy] = {
      ...(config.request_defaults[policy] || {}),
      ...(policy === 'portability' ? { transfer_requested: false, transfer_service_id: '' } : {}),
      ...value, request_id: value.request_id || randomUUID(),
      // Authenticated identity is authoritative, never an ID supplied by the client.
      user_id: userId, target_user_id: userId,
    };
  }
  if (policy === 'breach') input.breach = {
    ...config.breach_defaults, ...value, affected_users: [userId],
  };
  try {
    res.json(await gdpr.route(policy, input, userId));
  } catch (error) {
    throw new ApiError(502, 'OPA evaluation failed');
  }
}));
router.use((error, req, res, next) => res.status(error.status || 500).json({ error: error.message }));
module.exports = router;
