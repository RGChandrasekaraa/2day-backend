const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const {
  getUserByEmail,
  createUser,
  updateUserCounter,
  getUserById,
} = require("./db");
const dotenv = require("dotenv");
dotenv.config();

// Use PORT provided in environment
const port = process.env.PORT;

const app = express();
app.use(express.json());
app.use(cookieParser());

const clientUrl = process.env.CLIENT_URL;
const RP_ID = process.env.RP_ID;


app.use(cors({ origin: clientUrl, credentials: true }));

app.get("/init-register", async (req, res) => {
  const { email, firstName, lastName, dob } = req.query;

  if (!email || !firstName || !lastName || !dob) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const existingUser = await getUserByEmail(email);
  if (existingUser) {
    return res.status(400).json({ error: "User already exists" });
  }

  const options = await generateRegistrationOptions({
    rpID: RP_ID,
    rpName: "Web Dev Simplified",
    userName: email,
  });

  res.cookie(
    "regInfo",
    JSON.stringify({
      userId: options.user.id,
      email,
      firstName,
      lastName,
      dob,
      challenge: options.challenge,
    }),
    { httpOnly: true, maxAge: 60000, secure: true }
  );

  res.json(options);
});


app.post("/verify-register", async (req, res) => {
  const regInfo = JSON.parse(req.cookies.regInfo);

  if (!regInfo) {
    return res.status(400).json({ error: "Registration info not found" });
  }

  const verification = await verifyRegistrationResponse({
    response: req.body,
    expectedChallenge: regInfo.challenge,
    expectedOrigin: clientUrl,
    expectedRPID: RP_ID,
  });

  if (verification.verified) {
    await createUser(regInfo.userId, regInfo.email, {
      firstName: regInfo.firstName,
      lastName: regInfo.lastName,
      dob: regInfo.dob,
      id: verification.registrationInfo.credentialID,
      publicKey: Buffer.from(verification.registrationInfo.credentialPublicKey), // Store publicKey as Buffer
      counter: verification.registrationInfo.counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
      transport: req.body.transports,
    });
    res.clearCookie("regInfo");
    return res.json({ verified: verification.verified });
  } else {
    return res
      .status(400)
      .json({ verified: false, error: "Verification failed" });
  }
});


app.get("/init-auth", async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const user = await getUserByEmail(email);
  if (user == null) {
    return res.status(400).json({ error: "No user for this email" });
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: [
      {
        id: user.passKey.id,
        type: "public-key",
        transports: user.passKey.transports,
      },
    ],
  });

  res.cookie(
    "authInfo",
    JSON.stringify({
      userId: user._id, // Use _id from MongoDB
      challenge: options.challenge,
    }),
    { httpOnly: true, maxAge: 60000, secure: true }
  );

  res.json(options);
});

app.post("/verify-auth", async (req, res) => {
  const authInfo = JSON.parse(req.cookies.authInfo);

  if (!authInfo) {
    return res.status(400).json({ error: "Authentication info not found" });
  }

  const user = await getUserById(authInfo.userId);
  if (user == null || user.passKey.id != req.body.id) {
    return res.status(400).json({ error: "Invalid user" });
  }

  const verification = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge: authInfo.challenge,
    expectedOrigin: clientUrl,
    expectedRPID: RP_ID,
    authenticator: {
      credentialID: user.passKey.id,
      credentialPublicKey: user.passKey.publicKey, // Use Buffer directly
      counter: user.passKey.counter,
      transports: user.passKey.transports,
    },
  });

  if (verification.verified) {
    await updateUserCounter(user._id, verification.authenticationInfo.newCounter);
    res.clearCookie("authInfo");
    return res.json({ verified: verification.verified });
  } else {
    return res
      .status(400)
      .json({ verified: false, error: "Verification failed" });
  }
});



// Listen on `port` and 0.0.0.0
app.listen(port, "0.0.0.0", function () {
  console.log(`Server running on port ${port}`);
});
