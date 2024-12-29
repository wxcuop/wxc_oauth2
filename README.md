# wxc_oauth2

## Overview
`wxc_oauth2` is a Google Apps Script-based implementation of an OAuth 2.0 server. It provides essential operations for handling application registration, user login, token exchange, and token validation. The project is designed to integrate with Google Sheets for managing client registrations, tokens, and logs.

## Features
- **OAuth 2.0 Authorization Code Flow**:
  - Application registration
  - User authentication
  - Authorization code issuance
  - Token exchange with PKCE support
- **Token Validation**: Validate access tokens for expiration and validity.
- **Google Sheets Integration**: Use Google Sheets to manage:
  - Registered clients
  - Issued tokens
  - Logs for debugging and monitoring

## Prerequisites
1. A Google account with access to Google Drive and Google Sheets.
2. A Google Apps Script project linked to a spreadsheet containing the following sheets:
   - **Clients**: For storing client ID, secret, app name, and redirect URI.
   - **Tokens**: For storing authorization codes, access tokens, and metadata.
   - **UserScopes**: For mapping users to clients and allowed scopes.
   - **Users**: For user credentials (username and password).
   - **Logs**: For logging operations.

## Setup
1. Create a new Google Sheet and add the required sheets (`Clients`, `Tokens`, `UserScopes`, `Users`, `Logs`).
2. Copy the provided Apps Script code into the script editor of the spreadsheet.
3. Deploy the script as a web app:
   - Go to **Extensions > Apps Script > Deploy > New Deployment**.
   - Select "Web app" and set appropriate permissions.

## API Endpoints

### `doGet(e)`
Handles GET requests.

- **Operation: `auth`**
  - Initiates the authorization process by verifying client details and redirecting users to log in.

### `doPost(e)`
Handles POST requests.

- **Operation: `register`**
  - Registers a new application by generating a client ID and secret.
- **Operation: `login`**
  - Authenticates a user and issues an authorization code.
- **Operation: `token`**
  - Exchanges an authorization code for an access token.
- **Operation: `validate_token`**
  - Validates an access token for expiration or misuse.

## Key Functions

### Application Registration (`handleAppRegistration`)
Registers a new application by:
- Generating a unique client ID and secret.
- Storing them in the `Clients` sheet.

### Authorization Request (`handleAuthorizationRequest`)
Handles the first step of OAuth 2.0 by:
- Verifying client ID and redirect URI.
- Issuing an authorization code with optional PKCE support.

### Token Exchange (`exchangeAuthorizationCodeForToken`)
Exchanges an authorization code for an access token while supporting PKCE verification.

### Token Validation (`validateAccessToken`)
Validates whether an access token is still valid or has expired.

### User Login (`handleLogin`)
Authenticates users using credentials stored in the `Users` sheet.

## Testing
The script includes test functions for verifying core functionality:
- Test user login (`testUserLogin`)
- Test application registration (`testAppRegistration`)
- Test authorization request (`testHandleAuthorizationRequest`)
- Test token exchange (`testExchangeAuthorizationCode`)
- Test token validation (`testValidateAccessToken`)

## Logs
All operations are logged in the `Logs` sheet for debugging and monitoring purposes.

## License
This project is licensed under the MIT License.
