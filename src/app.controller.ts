import { Controller, Get, HttpService, Query, Req, Res } from "@nestjs/common";
import { AppService } from "./app.service";
import * as nonce from "nonce";
import { ConfigService } from "@nestjs/config";
import { Request, Response } from "express";
import * as querystring from "querystring";
import * as crypto from "crypto";

@Controller("api")
export class AppController {
  readonly cbRoute = "api/shopify/callback";
  readonly forwardingAddress = `https://844d54688486.ngrok.io/${this.cbRoute}`;

  constructor(
    private readonly appService: AppService,
    private readonly appConfig: ConfigService,
    private readonly httpService: HttpService
  ) {}

  @Get("/shopify")
  async shopify(
    @Query("shop") shop: string,
    @Res({ passthrough: true }) response: Response
  ) {
    if (shop) {
      const apiKey = this.appConfig.get("SHOPIFY_API_KEY");
      const scopes = this.appConfig.get("SCOPES");

      const state = crypto.randomBytes(16).toString("hex");
      const basicURl = `https://${shop}/admin/oauth/authorize`;
      const installUrl = `${basicURl}?client_id=${apiKey}&scope=${scopes}&state=${state}&redirect_uri=${this.forwardingAddress}`;
      const today = new Date();
      const tomorrow = new Date();
      tomorrow.setDate(today.getDate() + 1);
      response.cookie("state", state, {
        sameSite: false,
        secure: true,
        domain: "844d54688486.ngrok.io",
        expires: tomorrow
      });
      response.redirect(302, installUrl);
    } else {
      return response.status(400).send("missing shop parameter");
    }
  }

  @Get("shopify/callback")
  async callback(@Query() query, @Req() request: Request, @Res() response) {
    const secret = this.appConfig.get("SHOPIFY_API_SECRET");
    const apiKey = this.appConfig.get("SHOPIFY_API_KEY");
    const { shop, hmac, code, state } = query;
    const stateCookie = request.cookies["state"];
    if (state !== stateCookie) {
      return response.status(403).send("Request origin cannot be verified");
    }
    if (shop && hmac && code) {
      if (shop && hmac && code) {
        const map = Object.assign({}, query);
        delete map["signature"];
        delete map["hmac"];
        const message = querystring.stringify(map);
        const providedHmac = Buffer.from(hmac, "utf-8");
        const generatedHash = Buffer.from(
          crypto.createHmac("sha256", secret).update(message).digest("hex"),
          "utf-8"
        );
        let hashEquals = false;
        // timingSafeEqual will prevent any timing attacks. Arguments must be buffers
        try {
          hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac);
          // timingSafeEqual will return an error if the input buffers are not the same length.
        } catch (e) {
          hashEquals = false;
        }

        if (!hashEquals) {
          return response.status(400).send("HMAC validation failed");
        }

        // DONE: Exchange temporary code for a permanent access token
        const accessTokenRequestUrl =
          "https://" + shop + "/admin/oauth/access_token";
        const accessTokenPayload = {
          client_id: apiKey,
          client_secret: secret,
          code
        };

        const accessTokenResponse = await this.httpService
          .post(accessTokenRequestUrl, {
            json: accessTokenPayload
          })
          .toPromise();
        const accessToken = accessTokenResponse.data.access_token;
        // DONE: Use access token to make API call to 'shop' endpoint
        const shopRequestUrl =
          "https://" + shop + "/admin/api/2020-01/shop.json";
        const shopRequestHeaders = {
          "X-Shopify-Access-Token": accessToken
        };
        try {
          const shopResponse = await this.httpService
            .get(shopRequestUrl, { headers: shopRequestHeaders })
            .toPromise();
          response.status(200).end(shopResponse);
        } catch (error) {
          response.status(error.statusCode).send(error.error.error_description);
        }
      } else {
        response.status(400).send("Required parameters missing");
      }
    }
  }
}
