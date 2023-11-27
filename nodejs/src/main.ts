import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import { join } from 'path';
import { Issuer, generators } from 'openid-client';
import { AES256Encrypt, AES256Decrypt } from './helpers';

const app = express();
const port = process.env.YESEM_CLIENT_API_PORT;
const encryptionSecret = Buffer.from(process.env.YESEM_CLIENT_SECRET_KEY, 'base64');

app.use(cookieParser());
app.use(express.static(join(__dirname, '../../public'), { extensions: ['html'] }));

async function main() {
  const yesemIssuer = await Issuer.discover(process.env.YESEM_CLIENT_OPENID_URL);
  const privateKey = JSON.parse(Buffer.from(process.env.YESEM_CLIENT_CLIENT_PRIVATE_JWK, 'base64').toString());

  const client = new yesemIssuer.Client({
    client_id: process.env.YESEM_CLIENT_CLIENT_ID,
    client_secret: process.env.YESEM_CLIENT_CLIENT_SECRET,
    redirect_uris: [process.env.YESEM_CLIENT_CLIENT_REDIRECT_URI],
    response_types: ['code'],
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'RS512'
  }, {
    keys: [privateKey]
  });

  app.get('/authenticate', (req, res) => {
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);
    const state = generators.state();

    const url = client.authorizationUrl({
      scope: process.env.YESEM_CLIENT_CLIENT_SCOPES,
      code_challenge,
      code_challenge_method: 'S256',
      state
    });

    const cookieOptions = {
      httpOnly: true,
      secure: true,
      maxAge: 300000 // 5 minutes in milliseconds
    };

    // These cookies need to be AES-256 encrypted so the user-agent (browser) can not read their values
    res.cookie('code_verifier', AES256Encrypt(code_verifier, encryptionSecret), cookieOptions);
    res.cookie('state', AES256Encrypt(state, encryptionSecret), cookieOptions);

    res.redirect(url);
  });

  app.get('/handleCallback', async(req, res) => {
    const params = client.callbackParams(req);

    const code_verifier = AES256Decrypt(req.cookies.code_verifier, encryptionSecret);
    const state = AES256Decrypt(req.cookies.state, encryptionSecret);

    if(!code_verifier || !state) {
      // Invalid PKCE parameters
      return res.status(403).end('Forbidden');
    }

    const tokenSet = await client.callback(process.env.YESEM_CLIENT_CLIENT_REDIRECT_URI, params, {
      code_verifier,
      state
    });

    // Use the ID Token to identify your user using the sub claim which has national identifier ID
    // Also additional claims like given_name and family_name are set in the token
    console.log('Received and verified the ID Token', tokenSet.id_token);

    // After the users identity is verified, establish your own session mechanism
    res.cookie('session', 'secureSessionJwt', { httpOnly: true, secure: true });

    // Don't forget to clean the cookies
    res.clearCookie('code_verifier');
    res.clearCookie('state');

    res.redirect('/authenticated');
  });

  app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
  });
}

main();
