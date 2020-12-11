import { NextApiRequest, NextApiResponse } from 'next';

import IAuth0Settings from '../settings';
import { decodeState } from '../utils/state';
import { ISession } from '../session/session';
import { parseCookies } from '../utils/cookies';
import { ISessionStore } from '../session/store';
import { IOidcClientFactory } from '../utils/oidc-client';
import getSessionFromTokenSet from '../utils/session';

export type CallbackOptions = {
  redirectTo?: string;
  onUserLoaded?: (
    req: NextApiRequest,
    res: NextApiResponse,
    session: ISession,
    state: Record<string, any>
  ) => Promise<{ session: ISession, options: { redirectTo: string } }>;
};

export default function callbackHandler(
  settings: IAuth0Settings,
  clientProvider: IOidcClientFactory,
  sessionStore: ISessionStore
) {
  return async (req: NextApiRequest, res: NextApiResponse, options?: CallbackOptions): Promise<void> => {
    if (!res) {
      throw new Error('Response is not available');
    }

    if (!req) {
      throw new Error('Request is not available');
    }

    // Parse the cookies.
    const cookies = parseCookies(req);

    // Require that we have a state.
    const state = cookies['a0:state'];
    if (!state) {
      throw new Error('Invalid request, an initial state could not be found');
    }

    // Execute the code exchange
    const client = await clientProvider();
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(settings.redirectUri, params, {
      state
    });
    const decodedState = decodeState(state);

    // Get the claims without any OIDC specific claim.
    let session = getSessionFromTokenSet(tokenSet);

    // Temporary hack from: https://github.com/auth0/nextjs-auth0/issues/139#issuecomment-694252150
    let callbackOptions;
    if (options && options.onUserLoaded) {
      const { session: _session, options: _options } = await options.onUserLoaded(req, res, session, decodedState);
      session = _session
      callbackOptions = _options
    }

    // Create the session.
    await sessionStore.save(req, res, session);
    // Redirect to the homepage or custom url
    const redirectTo = (callbackOptions && callbackOptions.redirectTo) || (options && options.redirectTo) || decodedState.redirectTo || '/';

    res.writeHead(302, {
      Location: redirectTo
    });
    res.end();
  };
}
