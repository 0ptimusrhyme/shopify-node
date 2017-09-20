const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const querystring = require('querystring');
const rp = require('request-promise');

// Get data from .env
const apiKey = process.env.API_KEY;
const apiSecret = process.env.API_SECRET;
const webAddress = process.env.WEB_ADDRESS;

// GET root route
app.get('/', (req, res) => {
  const shop = req.query.shop;
  if (shop) {
    const redirectUrl = webAddress + "auth";
    const scope = 'write_products';
    const oauthUrl = "https://" + shop +
    "/admin/oauth/authorize?client_id=" + apiKey +
    "&redirect_uri=" + redirectUrl +
    "&scope=" + scope;

    return res.redirect(oauthUrl);
  } else {
    return res.status(400).send('Missing shop param.')
  }
});

// GET auth route
app.get('/auth', (req, res) => {
  // Validate hmac
  const hmac = req.query.hmac;
  const code = req.query.code;
  const shop = req.query.shop

  if (shop && hmac && code) {
    const queryParams = req.query;
    delete queryParams['signature'];
    delete queryParams['hmac'];
    const message = querystring.stringify(queryParams);
    const generatedHash = crypto.createHmac('sha256', apiSecret).update(message).digest('hex');

    if (generatedHash !== hmac) {
      res.status(400).send('HMAC validation failed');
    }

    const accessTokenUrl = "https://" + shop + "/admin/oauth/access_token";
    const tokenPayload = {
      client_id: apiKey,
      client_secret: apiSecret,
      code
    };

    rp.post(accessTokenUrl, { json: tokenPayload })
    .then((accessTokenResponse) => {
      const accessToken = accessTokenResponse.access_token;
      const shopRequestURL = "https://" + shop + "/admin/shop.json";
      const shopRequestHeaders = { 'x-shopify-access-token': accessToken };
      rp.get(shopRequestURL, { headers: shopRequestHeaders })
      .then((shopResponse) => {
        res.send(shopResponse)
        .catch((error) => {
          res.status(error.statusCode).send(error.error.error_description);
        });
      });
    }).catch((error) => {
      res.status(error.statusCode).send(error.error.error_description);
    });
  } else {
    res.status(400).send('Required parameters missing')
  }
});

app.listen(4567, () => {
  console.log('Example app listening on port 4567!');
});
