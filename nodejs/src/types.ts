declare global {
  namespace NodeJS {
    interface ProcessEnv {
      YESEM_CLIENT_API_PORT: string;
      YESEM_CLIENT_OPENID_URL: string;
      YESEM_CLIENT_CLIENT_ID: string;
      YESEM_CLIENT_CLIENT_SECRET: string;
      YESEM_CLIENT_CLIENT_REDIRECT_URI: string;
      YESEM_CLIENT_CLIENT_SCOPES: string;
      YESEM_CLIENT_CLIENT_PRIVATE_JWK: string;
      YESEM_CLIENT_SECRET_KEY: string;
    }
  }
}

export {};
