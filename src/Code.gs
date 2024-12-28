// Project: wxc_oauth2
// License: MIT
// Main entry points for handling GET and POST requests
function doGet(e) {
  const operation = e.parameter.operation;

  if (operation === "auth") {
    return handleAuthorizationRequest(e);
  }
}

function doPost(e) {
  const operation = e.parameter.operation;
  const grantType = e.parameter.grant_type; //Align with OAuth2 standards

  if (operation === "register") {
    return handleAppRegistration(e); // Handles application registration
  } else if (operation === "login") {
    return handleLogin(e); // Handles user login
  } else if (operation === "token" || grantType === "authorization_code") {
    return exchangeAuthorizationCodeForToken(e); // Handles token exchange
  }

  return ContentService.createTextOutput("Invalid operation").setMimeType(ContentService.MimeType.TEXT);
}

// Handle application registration (Step 0 of OAuth2)
function handleAppRegistration(e) {
  try {
    const appName = e.parameter.app_name;
    const redirectUri = e.parameter.redirect_uri;

    // Validate required parameters
    if (!appName || !redirectUri) {
      return ContentService.createTextOutput("Missing required parameters: app_name and redirect_uri").setMimeType(ContentService.MimeType.TEXT);
    }

    // Generate a unique client ID and secret
    const clientId = generateUUID();
    const clientSecret = generateUUID();

    // Save the app registration in the "Clients" sheet
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Clients");
    if (!sheet) {
      throw new Error("Clients sheet not found.");
    }
    sheet.appendRow([clientId, clientSecret, appName, redirectUri]);
    logToSheet(`Application registered successfully: ${appName}`)
    // Return the client ID and secret to the application
    return ContentService.createTextOutput(JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      message: "Application registered successfully"
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    logToSheet(`Error in handleAppRegistration: ${error.message}`);
    return ContentService.createTextOutput("An error occurred during registration.").setMimeType(ContentService.MimeType.TEXT);
  }
}


// Handle authorization requests (Step 1 of OAuth2)
function handleAuthorizationRequest(e) {
  try {
    const clientId = e.parameter.client_id;
    const redirectUri = e.parameter.redirect_uri;
    const codeChallenge = e.parameter.code_challenge; // PKCE code challenge
    const codeChallengeMethod = e.parameter.code_challenge_method || "plain"; // Defaults to plain if not provided

    // Verify client ID and redirect URI
    if (!verifyClientIdRedirectURI(clientId, redirectUri)) {
      return ContentService.createTextOutput("Invalid Client ID or Redirect URI").setMimeType(ContentService.MimeType.TEXT);
    }

    // Generate an authorization code
    const authCode = generateUUID();

    // Save the authorization code along with the code challenge in the Tokens sheet
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Tokens");
    sheet.appendRow([authCode, "", new Date().toISOString(), codeChallenge, codeChallengeMethod, clientId]);
    logToSheet(`handleAuthorizationRequest: authorization code ${authCode} for ${clientId} created`)
    // Redirect back to the client with the authorization code
    return HtmlService.createHtmlOutput(`
      <script>
        window.location.href = "${redirectUri}?code=${authCode}";
      </script>
    `);
  } catch (error) {
    logToSheet(`Error in handleAuthorizationRequest: ${error.message}`);
    return ContentService.createTextOutput("An error occurred while processing your request.").setMimeType(ContentService.MimeType.TEXT);
  }
}

// Exchange authorization code for access token (Step 3 of OAuth2)
function exchangeAuthorizationCodeForToken(e) {
  try {
    const authCode = e.parameter.code;
    const clientId = e.parameter.client_id;
    const clientSecret = e.parameter.client_secret; // Optional for confidential clients
    const codeVerifier = e.parameter.code_verifier; // PKCE code verifier

    if (!authCode || !clientId) {
      logToSheet(`Missing required parameters: code or client_id: ${e}`);
      throw new Error("Missing required parameters: code or client_id.");
    }

    // Validate client ID and secret (if provided)
    const clientsSheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Clients");
    const clientsData = clientsSheet.getDataRange().getValues();
    let isValidClient = false;

    for (let i = 1; i < clientsData.length; i++) { // Skip header row
      if (clientsData[i][0] === clientId) { // Match Client ID
        if (clientSecret && clientsData[i][1] !== clientSecret) {
          logToSheet(`Invalid client_secret: ${e}`);

          throw new Error("Invalid client_secret.");
        }
        isValidClient = true;
        break;
      }
    }

    if (!isValidClient) {
        logToSheet(`Invalid client_secret: ${e}`)
    }

    // Retrieve the Tokens sheet
    const tokensSheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Tokens");
    const tokensData = tokensSheet.getDataRange().getValues();

    for (let i = 1; i < tokensData.length; i++) { // Skip header row
      if (tokensData[i][0] === authCode && tokensData[i][5] === clientId) { // Match authorization code and client ID
        const storedCodeChallenge = tokensData[i][3]; // Column D: Code Challenge
        const storedCodeChallengeMethod = tokensData[i][4]; // Column E: Code Challenge Method

        if (storedCodeChallenge) { // If PKCE is used
          if (!codeVerifier) {
            logToSheet(`Missing code_verifier for PKCE: ${e}`)
            throw new Error("Missing code_verifier for PKCE.");
          }

          if (storedCodeChallengeMethod === "S256") {
            const hashedVerifier = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, codeVerifier)
              .map(b => ('0' + (b & 0xFF).toString(16)).slice(-2))
              .join('');
            if (hashedVerifier !== storedCodeChallenge) {
            logToSheet(`Invalid code_verifier for S256: ${e}`)             
              throw new Error("Invalid code_verifier for S256.");
            }
          } else if (storedCodeChallengeMethod === "plain") {
            if (codeVerifier !== storedCodeChallenge) {
              logToSheet(`Invalid code_verifier for plain: ${e}`)             
              throw new Error("Invalid code_verifier for plain.");
            }
          } else {
            logToSheet(`Unsupported code_challenge_method: ${e}`)             
            throw new Error("Unsupported code_challenge_method.");
          }
        }

        // Generate an access token
        const accessToken = generateUUID();

        // Save access token in Tokens sheet
        tokensSheet.getRange(i + 1, 2).setValue(accessToken); // Column B: Access Token
        logToSheet(`exchangeAuthorizationCodeForToken: ${accessToken} created for ${clientId}`)
        return ContentService.createTextOutput(JSON.stringify({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 3600
        })).setMimeType(ContentService.MimeType.JSON);
      }
    }

    throw new Error("Invalid authorization code.");
  } catch (error) {
    logToSheet(`Error in exchangeAuthorizationCodeForToken: ${error.message}`);
    return ContentService.createTextOutput(error.message).setMimeType(ContentService.MimeType.TEXT);
  }
}



// Helper function to verify client ID and redirect URI
function verifyClientIdRedirectURI(clientId, redirectUri) {
  try {
    const sheet =SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Clients");
    
    const data = sheet.getDataRange().getValues();
    
    for (let i = 1; i < data.length; i++) { // Skip header row
      if (data[i][0] === clientId && data[i][3] === redirectUri) { //redirectUri in D
        return true;
      }
    }
    
    return false;

  } catch (error) {
    logToSheet(`Error verifying Client ID and Redirect URI: ${error.message}`);
    return false;
  }
}

// Helper function to verify user credentials
function verifyLoginPassword(username, password) {
  try {
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Users");
    
    const data = sheet.getDataRange().getValues();

    for (let i = 1; i < data.length; i++) { // Skip header row
      if (data[i][0] === username && data[i][1] === password) {
        return true;
      }
    }

    return false;

  } catch (error) {
    logToSheet(`Error verifying login credentials: ${error.message}`);
    return false;
  }
}

// Helper function to generate a unique identifier (UUID)
function generateUUID() {
  return Utilities.getUuid();
}

// Test function for verifying user login
function testUserLogin() {
  const testUsername = "user@example.com"; // Replace with test username
  const testPassword = "password123";      // Replace with test password

  const result = verifyLoginPassword(testUsername, testPassword); 
  logToSheet(`User login result: ${result ? "Success" : "Failure"}`);
}

// Test function for exchanging an authorization code for an access token
function testExchangeAuthorizationCode() {
  const testAuthCode = "auth_code_123"; // Replace with a valid test authorization code

  try {
    exchangeAuthorizationCodeForToken({ parameter: { code: testAuthCode } });
    
  } catch (error) {
    logToSheet(`Test failed: ${error.message}`);
  }
}

function logToSheet(message, details = "") {
  try {
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Logs");
    if (!sheet) {
      throw new Error("Logs sheet not found.");
    }
    const timestamp = new Date();
    sheet.appendRow([timestamp, message, details]);
  } catch (error) {
    console.error(`Error logging to sheet: ${error.message}`);
  }
}

