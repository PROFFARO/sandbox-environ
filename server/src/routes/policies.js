/**
 * Policies API Routes
 */

import { Router } from 'express';
import { getPolicy, getAllPolicies } from '../sandbox/policyEnforcer.js';

const router = Router();

/**
 * GET /api/policies — Get all policies
 */
router.get('/', (req, res) => {
  try {
    const policies = getAllPolicies();
    res.json(policies);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get policies: ' + err.message });
  }
});

/**
 * GET /api/policies/:language — Get language-specific policy
 */
router.get('/:language', (req, res) => {
  try {
    const policy = getPolicy(req.params.language);
    if (!policy) {
      return res.status(404).json({ error: `No policy found for language: ${req.params.language}` });
    }
    res.json(policy);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get policy: ' + err.message });
  }
});

export default router;
