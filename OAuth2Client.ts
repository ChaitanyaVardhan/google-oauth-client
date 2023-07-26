import queryString from "query-string";
import EventEmitter from "eventemitter3";
import _Layerr from "layerr";
import { handleBadResponse } from "./request.js";
import { fetch } from "@buttercup/fetch";

import {
    ERR_REFRESH_FAILED,
    GOOGLE_OAUTH2_AUTH_BASE_URL,
    GOOGLE_OAUTH2_TOKEN_URL
} from "./symbols.js";


import {
    GoogleToken
} from "./types.js";

interface GoogleTokenResponse {
    res: any;
    tokens: GoogleToken;
}

export class OAuth2Client extends EventEmitter {
    protected _accessToken: string;
    protected _clientID: string;
    protected _clientSecret: string;
    protected _fetch: typeof fetch;
    protected _redirectUrl: string;
    protected _refreshToken: string;
    protected _refreshTokenPromises: Map<string, Promise<GoogleTokenResponse>> = null;

    constructor(clientID: string, clientSecret: string, oauthRedirectURL: string) {
        super()
        this._clientID = clientID;
        this._clientSecret = clientSecret;
        this._accessToken = '';
        this._refreshToken = '';
        this._refreshTokenPromises = new Map();
        this._fetch = fetch;
    }

    get accessToken() {
        return this._accessToken;
    }

    get refreshToken() {
        return this._refreshToken;
    }

    generateAuthURL(config: {
        access_type: string;
        prompt: string;
        response_type?: string;
        scope: Array<string> | string;
    }) {
        const {
            access_type,
            scope: rawScope,
            prompt,
            response_type = "code",
        } = config

        const scope = Array.isArray(rawScope) ? rawScope.join(" ") : rawScope;
        const opts = {
            access_type,
            scope,
            prompt,
            response_type,
            client_id: this._clientID,
            redirect_uri: this._redirectUrl
        };
        return `${GOOGLE_OAUTH2_AUTH_BASE_URL}?${queryString.stringify(opts)}`

    }

    async exchangeAuthCodeForToken(authCode: string): Promise<GoogleTokenResponse> {
        const decodedAuthCode = decodeURIComponent(authCode)
        const data = {
            code: decodedAuthCode,
            client_id: this._clientID,
            client_secret: this._clientSecret,
            redirect_uri: this._redirectUrl,
            grant_type: "authorization code",
        };
        const res = await this._fetch(GOOGLE_OAUTH2_TOKEN_URL, {
            method: "POST",
            body: queryString.stringify(data),
            headers: {
                "Content-type": "application/x-www-form-urlencoded"
            }
        })
        handleBadResponse(res)
        const tokens = await res.json() as {
            access_token: string;
            expires_in?: number;
            expiry_date?: number;
            // refresh_token: string; 
        };
        if (tokens && tokens.expires_in) {
            tokens.expiry_date = new Date().getTime() + tokens.expires_in * 1000;
            delete tokens.expires_in;
        }
        this._accessToken = tokens.access_token
        // this._refreshToken = tokens.refresh_token
        this.emit("tokens", tokens)
        return {
            tokens,
            res
        };
    }
}
