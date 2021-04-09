const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const atob = require('atob');
const cookieParser = require('cookie-parser');
const path = require("path");
const USERS = require("./users.json")

// env vars
const JWK_URL = process.env.JWKS_URL || "https://www.googleapis.com/oauth2/v3/certs"
const PORT = process.env.PORT || 8888


const JWK_CLIENT = jwksClient({
    jwksUri: JWK_URL,
});


const getToken = function(req) {
  if (req.headers.authorization &&
    req.headers.authorization.split(' ')[0] === 'Bearer') { // Authorization: Bearer g1jipjgi1ifjioj
    // Handle token presented as a Bearer token in the Authorization header
    return req.headers.authorization.split(' ')[1];
  } else if (req.query && req.query.token) {
    // Handle token presented as URI param
    return req.query.token;
  } else if (req.cookies && req.cookies.token) {
    // Handle token presented as a cookie parameter
    return req.cookies.token;
  }
};


function getJwtKid(token) {
  var base64Url = token.split('.')[0];
  var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  var jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));

  return JSON.parse(jsonPayload).kid;
};


const app = express();
app.use(cookieParser());


function authCheck(req, res, next){
  let raw_token = getToken(req)
  if (! raw_token){
    console.error("no token");
    res.status(401).send({
      'err': "no token provided",
    });
  }
  JWK_CLIENT.getSigningKey(getJwtKid(raw_token), (err, key) => {
      if (err) {
        console.error(err);
        res.status(401).send({
          'err': err,
        });
      } else {
        const useKey = key.publicKey || key.rsaPublicKey;
        let token = jwt.verify(raw_token, useKey)
        if (USERS.indexOf(token.email) >=0){
          next()
        } else {
          console.error("user " + token.email + " tried to access")
          res.status(401).send({
            'err': "user not allowed",
          });
        }
      }
    });
}

// use this static public
app.use(express.static("./static"))

// hold data back
app.use("/private", authCheck)
app.use("/private", express.static(path.join(__dirname, 'private')))


app.listen(PORT, () => console.log('listening on ' + PORT));
