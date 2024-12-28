# OAuth2 Provider Implementation in Google Apps Script

This repository contains a Google Apps Script implementation of an OAuth2 provider with support for **client_secret** (confidential clients) and **PKCE** (public clients). The provider includes endpoints for application registration, user authentication, authorization code generation, and token exchange.

---

## Features

1. **Application Registration**:
   - Allows external applications to register and receive a `client_id` and `client_secret`.
   - Stores app details in the `Clients` sheet.

2. **Authorization Flow**:
   - Supports both **client_secret** and **PKCE**.
   - Generates authorization codes and redirects users to the specified redirect URI.

3. **Token Exchange**:
   - Exchanges authorization codes for access tokens.
   - Validates both `client_secret` (for confidential clients) and `code_verifier` (for PKCE).

4. **Logging**:
   - Logs important events and errors to a `Logs` sheet for debugging purposes.

5. **Testing Functions**:
   - Includes test functions for user login and token exchange.

---

## Sheets Setup

### 1. **Clients Sheet**
Stores registered applications.

| Client ID     | Client Secret       | App Name         | Redirect URI           |
|---------------|---------------------|------------------|------------------------|
| client_12345  | secret_67890        | My Test App       | http://localhost/callback |

---

### 2. **Tokens Sheet**
Tracks issued authorization codes, access tokens, and PKCE-related fields.

| Authorization Code | Access Token       | Timestamp               | Code Challenge         | Code Challenge Method | Client ID     |
|---------------------|--------------------|--------------------------|------------------------|-----------------------|---------------|
| auth_code_123       | access_token_abc  | 2024-12-28T00:00:00Z     | hashed_code_challenge  | S256                 | client_12345 |

---

### 3. **Users Sheet**
Stores user credentials for authentication.

| Username            | Password          |
|----------------------|-------------------|
| user@example.com     | password123       |

---

### 4. **Logs Sheet**
Records logs for debugging purposes.

| Timestamp           | Message                          | Details                                      |
|---------------------|----------------------------------|---------------------------------------------|
| 2024-12-28 00:00:00 | Starting handleLogin...          | {"username":"user@example.com"}             |

---

## Endpoints

### 1. Application Registration (`/register`)
Registers a new application with the OAuth2 provider.

#### Request
```bash
curl -X POST \
-d "operation=register" \
-d "app_name=My Test App" \
-d "redirect_uri=http://localhost/callback" \
"https://script.google.com/macros/s/YOUR_DEPLOYMENT_ID/exec"
```

#### Response
```json
{
  "client_id": "generated_client_id",
  "client_secret": "generated_client_secret",
  "redirect_uri": "http://localhost/callback",
  "message": "Application registered successfully"
}
```

---

### 2. Authorization Request (`/auth`)
Generates an authorization code for a registered application.

#### Request
```bash
curl -X GET \
"https://script.google.com/macros/s/YOUR_DEPLOYMENT_ID/exec?operation=auth&client_id=client_12345&redirect_uri=http://localhost/callback&response_type=code&code_challenge=HASHED_CODE_CHALLENGE&code_challenge_method=S256"
```

#### Response
Redirects the user to:
```
http://localhost/callback?code=auth_code_123
```

---

### 3. Token Exchange (`/token`)
Exchanges an authorization code for an access token.

#### Request with `client_secret`:
```bash
curl -X POST \
-d "operation=token" \
-d "client_id=client_12345" \
-d "client_secret=secret_67890" \
-d "code=auth_code_123" \
"https://script.google.com/macros/s/YOUR_DEPLOYMENT_ID/exec"
```

#### Request with PKCE:
```bash
curl -X POST \
-d "operation=token" \
-d "client_id=client_12345" \
-d "code=auth_code_123" \
-d "code_verifier=ORIGINAL_CODE_VERIFIER" \
"https://script.google.com/macros/s/YOUR_DEPLOYMENT_ID/exec"
```

#### Response
```json
{
  "access_token": "generated_access_token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

## Functions Overview

### Main Entry Points
- `doGet(e)`: Handles GET requests (e.g., `/auth`).
- `doPost(e)`: Handles POST requests (e.g., `/register`, `/login`, `/token`).

### Core Functions
1. `handleAppRegistration(e)`:
   - Registers applications and generates `client_id` and `client_secret`.

2. `handleAuthorizationRequest(e)`:
   - Validates client credentials.
   - Generates an authorization code.
   - Redirects to the specified redirect URI.

3. `exchangeAuthorizationCodeForToken(e)`:
   - Validates authorization codes.
   - Issues access tokens.
   - Supports both `client_secret` and PKCE validation.

4. Helper Functions:
   - `verifyClientIdRedirectURI(clientId, redirectUri)`: Validates client credentials.
   - `verifyLoginPassword(username, password)`: Verifies user credentials.
   - `generateUUID()`: Generates unique identifiers.
   - `logToSheet(message, details)`: Logs events to the Logs sheet.

---

## Deployment Instructions

1. Open the Google Apps Script editor.
2. Paste the code into a new project (`Code.gs`).
3. Create the required sheets (`Clients`, `Tokens`, `Users`, `Logs`) in your Google Spreadsheet.
4. Deploy as a Web App:
   - Go to `Deploy > New Deployment`.
   - Select `Web app`.
   - Set permissions to `"Anyone with the link"`.

---

## Testing

### Test User Login
Use the test function to verify user login functionality:
```javascript
function testUserLogin() {
    const testUsername = "user@example.com";
    const testPassword = "password123";
    const result = verifyLoginPassword(testUsername, testPassword);
    logToSheet(`User login result: ${result ? "Success" : "Failure"}`);
}
```

### Test Token Exchange
Use the test function to simulate token exchange:
```javascript
function testExchangeAuthorizationCode() {
    const testAuthCode = "auth_code_123";
    exchangeAuthorizationCodeForToken({ parameter: { code: testAuthCode } });
}
```

---

## License

This project is licensed under the MIT License.

---

Feel free to use this README.md file as a starting point for your GitHub repository! Let me know if you need additional details or clarifications!

Citations:
[1] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/21056446/f90f4d21-cb0d-40d5-bc44-7fc7492f9ce1/paste.txt
[2] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/21056446/c5e89714-17b6-42ae-86bc-d8a4352a601d/paste-2.txt
