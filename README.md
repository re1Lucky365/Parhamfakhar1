# Required OIDC params
input.query_params.client_id != ""
input.query_params.redirect_uri != ""
input.query_params.response_type != ""

# PKCE enforcement
input.query_params.code_challenge_method == "S256"
is_valid_s256_challenge(input.query_params.code_challenge)

# state freshness
input.query_params.state != ""
is_fresh_state(input.query_params.state)

# redirect_uri must match the registered client URIs
valid_redirect_for_client(input.query_params.client_id, input.query_params.redirect_uri)

# ensure response_type includes "code" for authorization code flow
contains_code_response_type(input.query_params.response_type)input.query_params.statepackage authz.oidc

import future.keywords.if
import future.keywords.in

default allow := false

allow if {
    input.http_request.method == "GET"
    input.http_request.path == "/oidc/authorize"

    input.query_params.code_challenge_method == "S256"
    is_valid_base64url(input.query_params.code_challenge)
    input.query_params.state != ""

    is_fresh_state(input.query_params.state)
}

is_fresh_state(state) if {
    session := data.active_sessions[state]
    session.used == false
}

is_valid_base64url(value) if {
    value != ""
    regex.match("^[A-Za-z0-9\\-_]+$", value)
    count(value) >= 43
    count(value) <= 128
}authz.oidcfuture.keywords.iffuture.keywords.ininput.http_request.methodinput.http_request.pathsession.usedhttps://share.gemini.google/wGLs6BxruZW6
package authz.oidc

import future.keywords.in

# Test 1: Valid OIDC request with PKCE S256 and valid CSRF state passes
test_valid_oidc_pkce_request {
    allow with input as {
        "http_request": {
            "method": "GET",
            "path": "/oidc/authorize"
        },
        "query_params": {
            "code_challenge_method": "S256",
            "code_challenge": "vff51QGnDrw_lQ17PjfQhkk0Uz7C8mQP7ncBwgYsBmA",
            "state": "valid_fresh_csrf_token_12345"
        }
    } with data.active_sessions as {
        "valid_fresh_csrf_token_12345": {"used": false}
    }
}

# Test 2: Reject request lacking PKCE (code_challenge_method missing or invalid)
test_reject_missing_pkce {
    not allow with input as {
        "http_request": {
            "method": "GET",
            "path": "/oidc/authorize"
        },
        "query_params": {
            "code_challenge_method": "plain",
            "code_challenge": "short_token",
            "state": "valid_fresh_csrf_token_12345"
        }
    }
}

# Test 3: Reject replayed state token (CSRF token reuse attempt)
test_reject_reused_csrf_token {
    not allow with input as {
        "http_request": {
            "method": "GET",
            "path": "/oidc/authorize"
        },
        "query_params": {
            "code_challenge_method": "S256",
            "code_challenge": "vff51QGnDrw_lQ17PjfQhkk0Uz7C8mQP7ncBwgYsBmA",
            "state": "reused_csrf_token_99999"
        }
    } with data.active_sessions as {
        "reused_csrf_token_99999": {"used": true}
    }
}
authz.oidcfuture.keywords.inserver {
    listen 80;
    server_name auth-gateway.internal.domain.com;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self';" always;

    location /oidc/authorize {
        # Intercept and validate PKCE method before forwarding
        if ($arg_code_challenge_method != "S256") {
            return 400 '{"error": "invalid_request", "error_description": "PKCE code_challenge_method=S256 is strictly required."}';
        }

        # Query OPA engine for continuous authorization check
        proxy_pass http://opa:8181/v1/data/authz/oidc/allow;
        proxy_set_header Content-Type "application/json";
    }

    location / {
        return 403 '{"error": "access_denied", "message": "Zero Trust ingress policy denied access."}';
    }
}
auth-gateway.internal.domain.comvariable "cloudflare_api_token" {
  type        = string
  description = "Cloudflare API Token with Access Application permissions"
  sensitive   = true
}

variable "cloudflare_zone_id" {
  type        = string
  description = "Target Cloudflare Zone ID"
}

variable "okta_idp_id" {
  type        = string
  description = "Okta Identity Provider ID registered in Cloudflare Access"
}

variable "allowed_employee_group_id" {
  type        = string
  description = "ID of the approved Access Group for hardware passkey users"
}
data.authz.oidc.test_valid_oidc_pkce_request: PASS
data.authz.oidc.test_reject_missing_pkce: PASS
data.authz.oidc.test_reject_reused_csrf_token: PASS
--------------------------------------------------------------------------------
PASS: 3/3
400403auth-gateway.internal.domain.comserver {
    listen 80;
    server_name auth-gateway.internal.domain.com;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self';" always;

    location /oidc/authorize {
        # Intercept and validate PKCE method before forwarding
        if ($arg_code_challenge_method != "S256") {
            return 400 '{"error": "invalid_request", "error_description": "PKCE code_challenge_method=S256 is strictly required."}';
        }

        # Query OPA engine for continuous authorization check
        proxy_pass http://opa:8181/v1/data/authz/oidc/allow;
        proxy_set_header Content-Type "application/json";
    }

    location / {
        return 403 '{"error": "access_denied", "message": "Zero Trust ingress policy denied access."}';
    }
}
future.keywords.in3/docker compose up -d
To build a complete enterprise-grade, zero-trust cybersecurity environment with global telemetry, we must move past legacy perimeter security. Modern threats—such as the recent OIDC logic flaws in Meta’s High Touch Support system and the global Canvas LMS cross-site injection incidents—demonstrate that identity is the new perimeter and session tokens are the main attack surface.
The architecture below outlines an automated end-to-end framework across all four layers of Enterprise Zero Trust and Global IT Monitoring.
Architecture Overview
 [ Untrusted Users & Devices ]
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│   1. Identity Context & Zero Trust Network Access (ZTNA) │
│      • Mutual TLS (mTLS) + Hardware Keys (FIDO2)          │
│      • Continuous Access Evaluation Protocol (CAEP)       │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│   2. App Layer Security & API Protection                 │
│      • Mandatory OIDC with PKCE (S256 enforcement)       │
│      • Ephemeral, Cryptographically Bound Tokens         │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│   3. Endpoint Protection & Infrastructure Isolation      │
│      • Ephemeral Sandboxed Containers / Micro-VMs         │
│      • Hardware-enforced isolation (e.g., Muse/Hyper-V)   │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│   4. Global Enterprise Monitoring & SOC Operations       │
│      • Real-Time SIEM/SOAR Ingestion & Automated Mitigation│
└──────────────────────────────────────────────────────────┘

Layer Breakdown & Configuration Standards
 1. Identity Provider & ZTNA Enforcement
   Authentication Layer
   Enforce strict continuous access evaluation. Deny legacy authentication methods and require hardware-backed passkeys or WebAuthn tokens to defeat Adversary-in-the-Middle (AiTM) phishing.
   * Policy: Authenticate device health via mTLS before granting endpoint network ingress.
   * Session Duration: Limit access token lifespans to 15 minutes; mandate immediate re-verification upon state change (IP shift, anomalous user-agent, or risky location).
   * Verification Check: Execute curl -I [https://auth.yourdomain.com](https://auth.yourdomain.com) from an uncertified device to verify it receives an immediate 403 Forbidden prior to any identity challenge.
 2. OIDC & API Gateway Security
   Application Layer
   Enforce Proof Key for Code Exchange (PKCE) with SHA-256 (code_challenge_method=S256) across all OpenID Connect flows. This neutralizes token interception and redirect-hijacking vectors.
   # Ingress Control Policy Example
location /oidc/authorize {
    if ($arg_code_challenge_method != "S256") {
        return 400 "PKCE with SHA-256 is strictly enforced.";
    }
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self';" always;
}

   * Verification Check: Send an authorization request lacking a code_challenge parameter to confirm the API Gateway rejects the request with HTTP 400 Bad Request.
 3. Infrastructure Sandboxing & Ephemeral Execution
   Compute Layer
   Isolate AI workloads, administrative utilities, and background processes within micro-VMs or containerized environments.
   * Zero-Egress Rule: Restrict outgoing workload egress strictly to required API domains via egress proxy filtering.
   * Verification Check: Attempt an outbound ICMP ping from an agent runtime container to an unlisted external IP to confirm dropping of non-whitelisted traffic.
 4. SIEM / SOAR Monitoring & Dynamic Response
   Ops & Telemetry Layer
   Unify logs across identity providers, network proxies, and workloads into a central Security Operations Center (SOC) dashboard. Automate token revocation upon anomaly detection.
   * Automated Action Pipeline: Connect OAuth token revoking webhooks directly to SIEM risk score alerts.
   * Verification Check: Trigger a test "Impossible Travel" synthetic event in your IdP test tenant to verify the SOAR engine revokes active sessions and resets the state within < 5 seconds.
Global SOC Threat Tracking Matrix
| Monitoring Vector | Primary Threat Target | Detection Telemetry Signal | Automated Remediation Rule |
|---|---|---|---|
| Identity & OIDC | Session Hijacking / Token Theft | Reused csrf_token, mismatching waterfall_id, missing PKCE challenge | Invalidate user session globally; terminate active OAuth refresh tokens. |
| API Endpoints | Logic Exploitation / Bypass | Rapid spike in AI-driven recovery or high-touch reset endpoints | Freeze endpoint access; route request flow to step-up step-authentication. |
| Developer Environments | Supply Chain / Extension Malware | Unauthorized egress traffic originating from IDE background processes | Isolate host machine; revoke developer active OAuth credentials and SSH keys. |
| User Interfaces | DOM Injection / XSS | Unapproved modifications to auth portal forms or script tags | Instantly drain traffic to fallback immutable static auth nodes. |
re1Lucky365@gmail.com200retodo1Love471@gmail.comxF7p45QF19X0RmDrkrqehttps://www.facebook.com/share/19mJket9jY/https://www.facebook.com/share/19fVX4jqDs/record's and spreadsheets and files and documents and devices key's and developers key's badges and permissions T-Mobile files documents spreadsheets and data breaches and Google accounts and passwords and computers and apps All Google timelines All accounts super backup since and restore https://share.gemini.google/wGLs6BxruZW6authz.oidcfuture.keywords.inserverauth-gateway.internal.domain.comvariable400403auth-gateway.internal.domain.comserverpackage authz.oidc

import future.keywords.in

# Test 1: Valid OIDC request with PKCE S256 and valid CSRF state passes
test_valid_oidc_pkce_request {
    allow with input as {
        "http_request": {
            "method": "GET",
            "path": "/oidc/authorize"
        },
        "query_params": {
            "code_challenge_method": "S256",
            "code_challenge": "vff51QGnDrw_lQ17PjfQhkk0Uz7C8mQP7ncBwgYsBmA",
            "state": "valid_fresh_csrf_token_12345"
        }
    } with data.active_sessions as {
        "valid_fresh_csrf_token_12345": {"used": false}
    }
}

# Test 2: Reject request lacking PKCE (code_challenge_method missing or invalid)
test_reject_missing_pkce {
    not allow with input as {
        "http_request": {
            "method": "GET",
            "path": "/oidc/authorize"
        },
        "query_params": {
            "code_challenge_method": "plain",
            "code_challenge": "short_token",
            "state": "valid_fresh_csrf_token_12345"
        }
    }
}

# Test 3: Reject replayed state token (CSRF token reuse attempt)
test_reject_reused_csrf_token {
    not allow with input as {
        "http_request": {
            "method": "GET",
            "path": "/oidc/authorize"
        },
        "query_params": {
            "code_challenge_method": "S256",
            "code_challenge": "vff51QGnDrw_lQ17PjfQhkk0Uz7C8mQP7ncBwgYsBmA",
            "state": "reused_csrf_token_99999"
        }
    } with data.active_sessions as {
        "reused_csrf_token_99999": {"used": true}
    }
}
server {
    listen 80;
    server_name auth-gateway.internal.domain.com;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self';" always;

    location /oidc/authorize {
        # Intercept and validate PKCE method before forwarding
        if ($arg_code_challenge_method != "S256") {
            return 400 '{"error": "invalid_request", "error_description": "PKCE code_challenge_method=S256 is strictly required."}';
        }

        # Query OPA engine for continuous authorization check
        proxy_pass http://opa:8181/v1/data/authz/oidc/allow;
        proxy_set_header Content-Type "application/json";
    }

    location / {
        return 403 '{"error": "access_denied", "message": "Zero Trust ingress policy denied access."}';
    }
}
auth-gateway.internal.domain.comTo build a complete enterprise-grade, zero-trust cybersecurity environment with global telemetry, we must move past legacy perimeter security. Modern threats—such as the recent OIDC logic flaws in Meta’s High Touch Support system and the global Canvas LMS cross-site injection incidents—demonstrate that identity is the new perimeter and session tokens are the main attack surface.
The architecture below outlines an automated end-to-end framework across all four layers of Enterprise Zero Trust and Global IT Monitoring.
Architecture Overview
 [ Untrusted Users & Devices ]
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│   1. Identity Context & Zero Trust Network Access (ZTNA) │
│      • Mutual TLS (mTLS) + Hardware Keys (FIDO2)          │
│      • Continuous Access Evaluation Protocol (CAEP)       │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│   2. App Layer Security & API Protection                 │
│      • Mandatory OIDC with PKCE (S256 enforcement)       │
│      • Ephemeral, Cryptographically Bound Tokens         │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│   3. Endpoint Protection & Infrastructure Isolation      │
│      • Ephemeral Sandboxed Containers / Micro-VMs         │
│      • Hardware-enforced isolation (e.g., Muse/Hyper-V)   │
└──────────────────────────────┬───────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│   4. Global Enterprise Monitoring & SOC Operations       │
│      • Real-Time SIEM/SOAR Ingestion & Automated Mitigation│
└──────────────────────────────────────────────────────────┘

Layer Breakdown & Configuration Standards
 1. Identity Provider & ZTNA Enforcement
   Authentication Layer
   Enforce strict continuous access evaluation. Deny legacy authentication methods and require hardware-backed passkeys or WebAuthn tokens to defeat Adversary-in-the-Middle (AiTM) phishing.
   * Policy: Authenticate device health via mTLS before granting endpoint network ingress.
   * Session Duration: Limit access token lifespans to 15 minutes; mandate immediate re-verification upon state change (IP shift, anomalous user-agent, or risky location).
   * Verification Check: Execute curl -I [https://auth.yourdomain.com](https://auth.yourdomain.com) from an uncertified device to verify it receives an immediate 403 Forbidden prior to any identity challenge.
 2. OIDC & API Gateway Security
   Application Layer
   Enforce Proof Key for Code Exchange (PKCE) with SHA-256 (code_challenge_method=S256) across all OpenID Connect flows. This neutralizes token interception and redirect-hijacking vectors.
   # Ingress Control Policy Example
location /oidc/authorize {
    if ($arg_code_challenge_method != "S256") {
        return 400 "PKCE with SHA-256 is strictly enforced.";
    }
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self';" always;
}

   * Verification Check: Send an authorization request lacking a code_challenge parameter to confirm the API Gateway rejects the request with HTTP 400 Bad Request.
 3. Infrastructure Sandboxing & Ephemeral Execution
   Compute Layer
   Isolate AI workloads, administrative utilities, and background processes within micro-VMs or containerized environments.
   * Zero-Egress Rule: Restrict outgoing workload egress strictly to required API domains via egress proxy filtering.
   * Verification Check: Attempt an outbound ICMP ping from an agent runtime container to an unlisted external IP to confirm dropping of non-whitelisted traffic.
 4. SIEM / SOAR Monitoring & Dynamic Response
   Ops & Telemetry Layer
   Unify logs across identity providers, network proxies, and workloads into a central Security Operations Center (SOC) dashboard. Automate token revocation upon anomaly detection.
   * Automated Action Pipeline: Connect OAuth token revoking webhooks directly to SIEM risk score alerts.
   * Verification Check: Trigger a test "Impossible Travel" synthetic event in your IdP test tenant to verify the SOAR engine revokes active sessions and resets the state within < 5 seconds.
Global SOC Threat Tracking Matrix
| Monitoring Vector | Primary Threat Target | Detection Telemetry Signal | Automated Remediation Rule |
|---|---|---|---|
| Identity & OIDC | Session Hijacking / Token Theft | Reused csrf_token, mismatching waterfall_id, missing PKCE challenge | Invalidate user session globally; terminate active OAuth refresh tokens. |
| API Endpoints | Logic Exploitation / Bypass | Rapid spike in AI-driven recovery or high-touch reset endpoints | Freeze endpoint access; route request flow to step-up step-authentication. |
| Developer Environments | Supply Chain / Extension Malware | Unauthorized egress traffic originating from IDE background processes | Isolate host machine; revoke developer active OAuth credentials and SSH keys. |
| User Interfaces | DOM Injection / XSS | Unapproved modifications to auth portal forms or script tags | Instantly drain traffic to fallback immutable static auth nodes. |
re1Lucky365@gmail.comhttps://www.facebook.com/share/19mJket9jY/https://www.facebook.com/share/19fVX4jqDs/# 💫About Me :

I'm Parham Fakhari, a passionate Full-Stack Developer, AI Engineer, and Game Developer based in Mashhad, Iran 🇮🇷.
With over 5 years of experience, I specialize in building powerful web applications, intelligent AI systems, mobile apps, and even operating systems from scratch.
Whether it's crafting Telegram Web3 bots, training AI models, or writing a Unix-like OS in C & Assembly — I'm all in.
-----------

من پرهام فخاری هستم، یک توسعه‌دهنده فول‌استک، مهندس هوش مصنوعی و توسعه‌دهنده بازی از مشهد 🇮🇷.
با بیش از 5 سال تجربه، در ساخت برنامه‌های وب قدرتمند، سیستم‌های هوش مصنوعی هوشمند، اپلیکیشن‌های موبایل و حتی سیستم‌عامل‌ها از صفر تخصص دارم.
چه ساخت ربات‌های وب۳ تلگرام، آموزش مدل‌های هوش مصنوعی، یا نوشتن یک سیستم‌عامل شبیه یونیکس با C و اسمبلی باشد — من کاملاً درگیر این کار هستم.

## 🌐Socials
[![Discord](https://img.shields.io/badge/Discord-%237289DA.svg?logo=discord&logoColor=white)](htttps://discord.gg/parhamfakhari) [![Facebook](https://img.shields.io/badge/Facebook-%231877F2.svg?logo=Facebook&logoColor=white)](https://facebook.com/parhamfakhari) [![Instagram](https://img.shields.io/badge/Instagram-%23E4405F.svg?logo=Instagram&logoColor=white)](https://instagram.com/nikantalk) [![LinkedIn](https://img.shields.io/badge/LinkedIn-%230077B5.svg?logo=linkedin&logoColor=white)](https://linkedin.com/in/parhamfakhari) [![Pinterest](https://img.shields.io/badge/Pinterest-%23E60023.svg?logo=Pinterest&logoColor=white)](https://pinterest.com/parhamfakhari) [![Reddit](https://img.shields.io/badge/Reddit-%23FF4500.svg?logo=Reddit&logoColor=white)](https://reddit.com/user/parhamfakhari) [![Stack Overflow](https://img.shields.io/badge/-Stackoverflow-FE7A16?logo=stack-overflow&logoColor=white)](https://stackoverflow.com/users/parhamfakhari) [![TikTok](https://img.shields.io/badge/TikTok-%23000000.svg?logo=TikTok&logoColor=white)](https://tiktok.com/@nikantalk) [![Twitter](https://img.shields.io/badge/Twitter-%231DA1F2.svg?logo=Twitter&logoColor=white)](https://twitter.com/parhamfakhari) 

# 💻Tech Stack
![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white) ![C#](https://img.shields.io/badge/c%23-%23239120.svg?style=for-the-badge&logo=c-sharp&logoColor=white) ![HTML5](https://img.shields.io/badge/html5-%23E34F26.svg?style=for-the-badge&logo=html5&logoColor=white) ![Ruby](https://img.shields.io/badge/ruby-%23CC342D.svg?style=for-the-badge&logo=ruby&logoColor=white) ![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white) ![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Perl](https://img.shields.io/badge/perl-%2339457E.svg?style=for-the-badge&logo=perl&logoColor=white) ![PHP](https://img.shields.io/badge/php-%23777BB4.svg?style=for-the-badge&logo=php&logoColor=white) ![Java](https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=java&logoColor=white) ![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E) ![CSS3](https://img.shields.io/badge/css3-%231572B6.svg?style=for-the-badge&logo=css3&logoColor=white) ![Apache Groovy](https://img.shields.io/badge/Apache%20Groovy-4298B8.svg?style=for-the-badge&logo=Apache+Groovy&logoColor=white) ![Firebase](https://img.shields.io/badge/firebase-%23039BE5.svg?style=for-the-badge&logo=firebase) ![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white) ![Azure](https://img.shields.io/badge/azure-%230072C6.svg?style=for-the-badge&logo=azure-devops&logoColor=white) ![Cloudflare](https://img.shields.io/badge/Cloudflare-F38020?style=for-the-badge&logo=Cloudflare&logoColor=white) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Angular](https://img.shields.io/badge/angular-%23DD0031.svg?style=for-the-badge&logo=angular&logoColor=white) ![Angular.js](https://img.shields.io/badge/angular.js-%23E23237.svg?style=for-the-badge&logo=angularjs&logoColor=white) ![Bootstrap](https://img.shields.io/badge/bootstrap-%23563D7C.svg?style=for-the-badge&logo=bootstrap&logoColor=white) ![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi) ![Express.js](https://img.shields.io/badge/express.js-%23404d59.svg?style=for-the-badge&logo=express&logoColor=%2361DAFB) ![Electron.js](https://img.shields.io/badge/Electron-191970?style=for-the-badge&logo=Electron&logoColor=white) ![Chart.js](https://img.shields.io/badge/chart.js-F5788D.svg?style=for-the-badge&logo=chart.js&logoColor=white) ![Chakra](https://img.shields.io/badge/chakra-%234ED1C5.svg?style=for-the-badge&logo=chakraui&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) ![jQuery](https://img.shields.io/badge/jquery-%230769AD.svg?style=for-the-badge&logo=jquery&logoColor=white) ![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens) ![OpenCV](https://img.shields.io/badge/opencv-%23white.svg?style=for-the-badge&logo=opencv&logoColor=white) ![NuxtJS](https://img.shields.io/badge/Nuxt-black?style=for-the-badge&logo=nuxt.js&logoColor=white) ![NodeJS](https://img.shields.io/badge/node.js-6DA55F?style=for-the-badge&logo=node.js&logoColor=white) ![Next JS](https://img.shields.io/badge/Next-black?style=for-the-badge&logo=next.js&logoColor=white) ![NestJS](https://img.shields.io/badge/nestjs-%23E0234E.svg?style=for-the-badge&logo=nestjs&logoColor=white) ![NPM](https://img.shields.io/badge/NPM-%23000000.svg?style=for-the-badge&logo=npm&logoColor=white) ![Meteor JS](https://img.shields.io/badge/meteorjs-%23d74c4c.svg?style=for-the-badge&logo=meteor&logoColor=white) ![React](https://img.shields.io/badge/react-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB) ![React Native](https://img.shields.io/badge/react_native-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB) ![React Router](https://img.shields.io/badge/React_Router-CA4245?style=for-the-badge&logo=react-router&logoColor=white) ![SASS](https://img.shields.io/badge/SASS-hotpink.svg?style=for-the-badge&logo=SASS&logoColor=white) ![Socket.io](https://img.shields.io/badge/Socket.io-black?style=for-the-badge&logo=socket.io&badgeColor=010101) ![Vuetify](https://img.shields.io/badge/Vuetify-1867C0?style=for-the-badge&logo=vuetify&logoColor=AEDDFF) ![Vue.js](https://img.shields.io/badge/vuejs-%2335495e.svg?style=for-the-badge&logo=vuedotjs&logoColor=%234FC08D) ![Threejs](https://img.shields.io/badge/threejs-black?style=for-the-badge&logo=three.js&logoColor=white) ![Apache](https://img.shields.io/badge/apache-%23D42029.svg?style=for-the-badge&logo=apache&logoColor=white) ![Apache Airflow](https://img.shields.io/badge/Apache%20Airflow-017CEE?style=for-the-badge&logo=Apache%20Airflow&logoColor=white) ![Apache Ant](https://img.shields.io/badge/Apache%20Ant-A81C7D?style=for-the-badge&logo=Apache%20Ant&logoColor=white) ![Nginx](https://img.shields.io/badge/nginx-%23009639.svg?style=for-the-badge&logo=nginx&logoColor=white) ![MySQL](https://img.shields.io/badge/mysql-%2300f.svg?style=for-the-badge&logo=mysql&logoColor=white) 	![Neo4J](https://img.shields.io/badge/Neo4j-008CC1?style=for-the-badge&logo=neo4j&logoColor=white) ![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white) ![MongoDB](https://img.shields.io/badge/MongoDB-%234ea94b.svg?style=for-the-badge&logo=mongodb&logoColor=white) ![Postgres](https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white) ![Redis](https://img.shields.io/badge/redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white) ![Canva](https://img.shields.io/badge/Canva-%2300C4CC.svg?style=for-the-badge&logo=Canva&logoColor=white) ![Adobe Dreamweaver](https://img.shields.io/badge/Adobe%20Dreamweaver-FF61F6.svg?style=for-the-badge&logo=Adobe%20Dreamweaver&logoColor=white) ![Adobe Illustrator](https://img.shields.io/badge/adobeillustrator-%23FF9A00.svg?style=for-the-badge&logo=adobeillustrator&logoColor=white) 	![Figma](https://img.shields.io/badge/figma-%23F24E1E.svg?style=for-the-badge&logo=figma&logoColor=white) ![NumPy](https://img.shields.io/badge/numpy-%23013243.svg?style=for-the-badge&logo=numpy&logoColor=white) ![Pandas](https://img.shields.io/badge/pandas-%23150458.svg?style=for-the-badge&logo=pandas&logoColor=white) ![PyTorch](https://img.shields.io/badge/PyTorch-%23EE4C2C.svg?style=for-the-badge&logo=PyTorch&logoColor=white) ![TensorFlow](https://img.shields.io/badge/TensorFlow-%23FF6F00.svg?style=for-the-badge&logo=TensorFlow&logoColor=white) ![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white) ![Postman](https://img.shields.io/badge/Postman-FF6C37?style=for-the-badge&logo=postman&logoColor=white) ![Swagger](https://img.shields.io/badge/-Swagger-%23Clojure?style=for-the-badge&logo=swagger&logoColor=white) ![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)
# 📊GitHub Stats :
![](https://github-readme-stats.vercel.app/api?username=parhamfakhar1&theme=vue-dark&hide_border=true&include_all_commits=true&count_private=true)<br/>
![](https://github-readme-streak-stats.herokuapp.com/?user=parhamfakhar1&theme=vue-dark&hide_border=true)<br/>
![](https://github-readme-stats.vercel.app/api/top-langs/?username=parhamfakhar1&theme=vue-dark&hide_border=true&include_all_commits=true&count_private=true&layout=compact)

### ✍️Random Dev Quote
![](https://quotes-github-readme.vercel.app/api?type=horizontal&theme=dark)

### 😂Random Dev Meme
<img src="https://random-memer.herokuapp.com/" width="512px"/>

---
[![](https://visitcount.itsvg.in/api?id=parhamfakhar1&icon=6&color=0)](https://visitcount.itsvg.in)

  ## 💰You can help me by Donating
  [![BuyMeACoffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/https://buymeacoffee.com/parhamfahari) 

  <!-- Proudly created with GPRM ( https://gprm.itsvg.in ) -->
  
