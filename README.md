# NexusCore Enterprise | Clean Rebuild v2

**SAML 2.0 + SCIM 2.0 | Microsoft Entra ID | Network Operations lab**

This rebuild replaces the original application code that rejected correctly signed assertions. It preserves the original clickable, Cisco-inspired dark network operations dashboard. Network data and diagnostics remain **simulated**. This is a training lab, not a production NOC.

## What changed, and why

The earlier version set `wantAssertionsSigned: true` but did not set `wantAuthnResponseSigned`, which defaults to `true` in Node-SAML. Your Entra signing option is **Sign SAML assertion**. That required a second signature on the *outer* response even though Entra sent a valid signed assertion, producing `Invalid document signature`.

The new SAML strategy explicitly requires and validates the signed assertion (`wantAssertionsSigned:true`) without demanding an outer response signature (`wantAuthnResponseSigned:false`). It still checks the Entra issuer, request correlation, audience/ACS, and the certificate signature. **Do not disable signature validation.**

We removed `SAML_ISSUER` from the configuration. The NexusCore Entity ID is always `APP_BASE_URL/saml/metadata`.

## Simple setup: only these steps

### 1. Replace the app code locally (PowerShell on your Windows PC)

Extract this new ZIP into a **new folder**. Do not merge it with the old extracted folder. Go into the extracted folder containing `package.json`:

```powershell
cd "$env:USERPROFILE\Downloads\NexusCore-Enterprise-REBUILT-SAML-SCIM"
Get-ChildItem
npm install
npm run check
```

If Windows created a nested folder, enter that folder before running `npm install`. You should see `server.js`, `package.json` and `public`.

### 2. Local dashboard check (no Entra changes)

```powershell
Copy-Item .env.example .env
npm start
```

Open `http://localhost:3000/preview` for the existing clickable NOC dashboard. Keep your **actual production secrets out of this local `.env`** unless doing intentional local tests.

### 3. Verify the downloaded public signing certificate (PowerShell on your Windows PC)

```powershell
node tools/check-certificate.js "$env:USERPROFILE\Downloads\NexusCore.cer"
```

Expected: `Certificate: VALID X.509` and a thumbprint. This checks the public certificate locally, without copying its PEM into chats.

### 4. Update your EXISTING GitHub repository (PowerShell on your Windows PC)

There is **no need** to create a new Enterprise application, SAML certificate, GitHub repository or Render service. Copy the rebuilt application files (except `.env`, `node_modules`, `data`) into your **existing local GitHub working folder**. Then verify changes:

```powershell
git status --short
git diff --check
git add server.js package.json README.md .env.example public tools tests
git diff --cached --name-only
git commit -m "Rebuild NexusCore SAML validation and add checks"
git push origin main
```

If your repository has a different branch, use that branch. **Always confirm** `.env`, tokens, and `node_modules` are absent before committing. If you're unsure of your repo working-folder path, use `git rev-parse --show-toplevel` while inside it.

### 5. Redeploy the EXISTING Render service

Render Dashboard → NexusCore service → **Manual Deploy → Deploy latest commit**, or allow its existing auto-deploy to run. **Do not create a second Render service.** Keep existing values:

| Render environment variable | Value |
|---|---|
| `APP_BASE_URL` | `https://nexuscore-enterprise-entra-saml-scim.onrender.com` |
| `ENTRA_LOGIN_URL` | Existing **Login URL** shown in Entra SAML configuration |
| `ENTRA_ISSUER` | Existing **Microsoft Entra Identifier** |
| `ENTRA_CERT_BASE64` | Your already verified PEM text from `NexusCore.cer` |
| `SESSION_SECRET` | Existing long random secret |
| `SCIM_BEARER_TOKEN` | Existing long random token |
| `NODE_ENV` | `production` |
| `DATA_DIR` | `./data` (ephemeral lab storage) |

**Remove `SAML_ISSUER`** from Render to avoid confusion: the rebuilt code does not read it. Do not regenerate certificates or secrets. Existing Entra Basic SAML Configuration remains:

- **Identifier:** `https://nexuscore-enterprise-entra-saml-scim.onrender.com/saml/metadata`
- **Reply URL (ACS):** `https://nexuscore-enterprise-entra-saml-scim.onrender.com/saml/acs`
- **Sign on URL:** `https://nexuscore-enterprise-entra-saml-scim.onrender.com/login`
- **Signing Option:** **Sign SAML assertion**; **Signing Algorithm:** SHA-256

### 6. Verify SAML and SCIM after deployment

1. Open `https://nexuscore-enterprise-entra-saml-scim.onrender.com/health`. It should show `samlConfigured:true` and `scimConfigured:true`.
2. Open a fresh InPrivate browser to `https://nexuscore-enterprise-entra-saml-scim.onrender.com/login` and sign in as your assigned Network Engineering user. Dashboard should open.
3. Only after SAML works, set up Entra SCIM **in the same existing Enterprise application**: Provisioning → Automatic; Tenant URL `https://nexuscore-enterprise-entra-saml-scim.onrender.com/scim/v2`, Secret Token is the existing Render `SCIM_BEARER_TOKEN`. Test Connection, then Provision on demand for a test user.
4. Confirm an active user appears under Identity & Access. Test a mapped title change and later user deactivation.

**Do not assume login passed until it has actually been tested against your tenant.** This package has source-level tests, but live Microsoft Entra authentication and SCIM provisioning must be verified in your lab.

## Important limits

- On Render Free, `./data` is ephemeral. SCIM users can disappear after restart/redeploy. Persistent storage is needed for durable provisioning.
- The Node.js session store is in-memory and not production-ready.
- The dashboard's devices, alerts, topology and connectivity measurements are demo data, not real infrastructure monitoring.
- An Entra group assignment controls SAML access; SCIM `active=false` alone does not end an existing SAML session.
- Keep `.env`, client secrets and SCIM tokens out of GitHub and screenshots.

## If SAML still fails

Check **Render → Logs** around the latest `/saml/acs` request and record *only the error message*, never the full SAML response. Do not rotate certificates or toggle signing requirements blindly. Debug the specific new error.
