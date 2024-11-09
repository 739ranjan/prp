import 'passport';

declare module 'passport' {
  interface Authenticator {
    authenticate(strategy: 'google-id-token', options?: any): any;
  }
}

declare namespace Express {
  interface User {
    id: string;
    email: string;
    name: string;
    picture: string;
  }

  export interface Request {
    user?: User;
  }
}
