const express = require('express');
const cookieParser = require('cookie-parser');
const path = require("path");

// env vars
const PASSPHRASE = process.env.PASSPHRASE || "privatefolder"
const PORT = process.env.PORT || 8989


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


const app = express();
app.use(cookieParser());


function authCheck(req, res, next){
  let passphrase = getToken(req)
  if (passphrase === PASSPHRASE){
    next()
  } else {
    res.status(401).send({
      'err': "Invalid passphrase.",
    });
  }
}

// use this static public
app.use(express.static("./static"))

// hold data back
app.use("/private", authCheck)
app.use("/private", express.static(path.join(__dirname, 'private')))


app.listen(PORT, () => console.log('listening on ' + PORT));
