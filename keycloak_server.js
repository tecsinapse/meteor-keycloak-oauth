Keycloak = {};

Keycloak.handleAuthFromAccessToken = function handleAuthFromAccessToken(
  accessToken,
  expiresAt
) {
  const whitelisted = [
    'email',
    'name',
    'given_name',
    'family_name',
    'picture',
    'preferred_username',
    'roles',
  ];

  const identity = getIdentity(accessToken);

  const serviceData = {
    accessToken,
    expiresAt,
    id: identity.sub,
    userId: identity.sub,
  };
  const fields = _.pick(identity, whitelisted);
  _.extend(serviceData, fields);

  const returnObj = {
    serviceData,
    options: { profile: { name: identity.name } },
  };
  return returnObj;
};

OAuth.registerService('keycloak', 2, null, function(query) {
  const response = getTokenResponse(query);
  const accessToken = response.accessToken;
  const expiresIn = response.expiresIn;

  const newResponse = Keycloak.handleAuthFromAccessToken(
    accessToken,
    +new Date() + 1000 * expiresIn
  );
  return newResponse;
});

// checks whether a string parses as JSON
const isJSON = function(str) {
  try {
    JSON.parse(str);
    return true;
  } catch (e) {
    return false;
  }
};

// returns an object containing:
// - accessToken
// - expiresIn: lifetime of token in seconds
var getTokenResponse = function(query) {
  const config = ServiceConfiguration.configurations.findOne({
    service: 'keycloak',
  });
  if (!config) throw new ServiceConfiguration.ConfigError();

  let responseContent;
  try {
    // Request an access token
    const params = {
      grant_type: 'authorization_code',
      client_id: config.clientId,
      redirect_uri: OAuth._redirectUri('keycloak', config),
      code: query.code,
    };
    if (config.secret) {
      params.client_secret = OAuth.openSecret(config.secret);
    }
    responseContent = HTTP.post(
      `${config.authServerUrl}/realms/${
        config.realm
      }/protocol/openid-connect/token`,
      {
        params,
      }
    ).data;
  } catch (err) {
    throw _.extend(
      new Error(
        `Failed to complete OAuth handshake with Keycloak. ${err.message}`
      ),
      { response: err.response }
    );
  }

  const kcAccessToken = responseContent.access_token;
  const kcExpires = responseContent.expires_in;

  if (!kcAccessToken) {
    throw new Error(
      `${'Failed to complete OAuth handshake with keycloak ' +
        "-- can't find access token in HTTP response. "}${
        responseContent}`
    );
  }
  return {
    accessToken: kcAccessToken,
    expiresIn: kcExpires,
  };
};

var getIdentity = function(accessToken) {
  const config = ServiceConfiguration.configurations.findOne({
    service: 'keycloak',
  });
  if (!config) throw new ServiceConfiguration.ConfigError();

  try {
    return HTTP.get(
      `${config.authServerUrl}/realms/${
        config.realm
      }/protocol/openid-connect/userinfo`,
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    ).data;
  } catch (err) {
    throw _.extend(
      new Error(`Failed to fetch identity from Keycloak. ${err.message}`),
      { response: err.response }
    );
  }
};

Keycloak.retrieveCredential = function(credentialToken, credentialSecret) {
  return OAuth.retrieveCredential(credentialToken, credentialSecret);
};
