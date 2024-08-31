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

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "https://2day-frontend.vercel.app");
    res.header("Access-Control-Allow-Credentials", "true");
    res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});


const app = express();
app.use(express.json());
app.use(cookieParser());

const clientUrl = process.env.CLIENT_URL;
const RP_ID = process.env.RP_ID;

app.use(cors({
    origin: true,
    credentials: true
}));

app.get("/init-register", async (req, res) => {
  try {
    const { email, firstName, lastName, dob } = req.query;

    console.log("init-register called with:", { email, firstName, lastName, dob });

    if (!email || !firstName || !lastName || !dob) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await getUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const options = await generateRegistrationOptions({
    rpID: RP_ID,
    rpName: "2Day App",
    userName: email,
    userDisplayName: `${firstName} ${lastName}`,
    authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "required", // Enforce biometric or other user verification
        requireResidentKey: false,
    },
    attestation: "none", // or "direct" if you need attestation data
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

    console.log("Registration options generated:", options);

    res.json(options);
  } catch (error) {
    console.error("Error in init-register:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/verify-register", async (req, res) => {
  try {
    const regInfo = req.cookies.regInfo;

    if (!regInfo) {
      console.error("Registration info not found in cookies");
      return res.status(400).json({ error: "Registration info not found" });
    }

    const parsedRegInfo = JSON.parse(regInfo);

    console.log("verify-register called with regInfo:", parsedRegInfo);

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: parsedRegInfo.challenge,
      expectedOrigin: clientUrl,
      expectedRPID: RP_ID,
    });

    console.log("Registration verification result:", verification);

    if (verification.verified) {
      await createUser(parsedRegInfo.userId, parsedRegInfo.email, {
        firstName: parsedRegInfo.firstName,
        lastName: parsedRegInfo.lastName,
        dob: parsedRegInfo.dob,
        id: verification.registrationInfo.credentialID,
        publicKey: Buffer.from(verification.registrationInfo.credentialPublicKey),
        counter: verification.registrationInfo.counter,
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
        transport: req.body.transports,
      });
      res.clearCookie("regInfo");
      return res.json({ verified: verification.verified });
    } else {
      return res.status(400).json({ verified: false, error: "Verification failed" });
    }
  } catch (error) {
    console.error("Error in verify-register:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


app.get("/init-auth", async (req, res) => {
  try {
    const email = req.query.email;

    console.log("init-auth called with:", { email });

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
    userVerification: "required", // Enforce biometric or other user verification
});


    console.log("Authentication options generated:", options);

    res.cookie(
      "authInfo",
      JSON.stringify({
        userId: user._id, // Use _id from MongoDB
        challenge: options.challenge,
      }),
      { httpOnly: true, maxAge: 60000, secure: true }
    );

    res.json(options);
  } catch (error) {
    console.error("Error in init-auth:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/verify-auth", async (req, res) => {
  try {
    const authInfo = JSON.parse(req.cookies.authInfo);

    console.log("verify-auth called with authInfo:", authInfo);

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

    console.log("Authentication verification result:", verification);

    if (verification.verified) {
      await updateUserCounter(user._id, verification.authenticationInfo.newCounter);
      res.clearCookie("authInfo");
      return res.json({ verified: verification.verified });
    } else {
      return res
        .status(400)
        .json({ verified: false, error: "Verification failed" });
    }
  } catch (error) {
    console.error("Error in verify-auth:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Listen on `port` and 0.0.0.0
app.listen(port, "0.0.0.0", function () {
  console.log(`Server running on port ${port}`);
});
