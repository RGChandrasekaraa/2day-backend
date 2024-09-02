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

console.log("Environment variables loaded:");
console.log("PORT:", port);
console.log("CLIENT_URL:", process.env.CLIENT_URL);
console.log("RP_ID:", process.env.RP_ID);

const app = express();
app.use(express.json());
app.use(cookieParser());

const clientUrl = process.env.CLIENT_URL || 'https://2day-frontend.vercel.app';
const RP_ID = process.env.RP_ID;

app.use(cors({ origin: clientUrl, credentials: true }));
app.use((req, res, next) => {
  console.log("CORS middleware processing request:");
  console.log("Origin:", req.headers.origin);
  console.log("Method:", req.method);
  console.log("Headers:", req.headers);

  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Origin', clientUrl);
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // If this is a preflight request, respond with 204 No Content
  if (req.method === 'OPTIONS') {
    console.log("Preflight request detected, responding with 204 No Content");
    return res.sendStatus(204);
  }

  next();
});


app.get("/init-register", async (req, res) => {
  try {
    const { email, firstName, lastName, dob } = req.query;

    console.log("init-register called with:", { email, firstName, lastName, dob });

    if (!email || !firstName || !lastName || !dob) {
      console.error("Required fields missing:", { email, firstName, lastName, dob });
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await getUserByEmail(email);
    console.log("Existing user check result:", existingUser);

    if (existingUser) {
      console.error("User already exists:", email);
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

    console.log("Generated registration options:", options);

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

    console.log("Registration info stored in cookie:", {
      userId: options.user.id,
      email,
      firstName,
      lastName,
      dob,
      challenge: options.challenge,
    });

    res.json(options);
  } catch (error) {
    console.error("Error in init-register:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/verify-register", async (req, res) => {
  try {
    const regInfo = req.cookies.regInfo;
    console.log("Cookie regInfo received:", regInfo);

    if (!regInfo) {
      console.error("Registration info not found in cookies");
      return res.status(400).json({ error: "Registration info not found" });
    }

    const parsedRegInfo = JSON.parse(regInfo);

    console.log("Parsed registration info:", parsedRegInfo);
    console.log("Request body received for verification:", req.body);

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
      console.log("User created successfully:", parsedRegInfo.email);

      res.clearCookie("regInfo");
      return res.json({ verified: verification.verified });
    } else {
      console.error("Verification failed:", verification);
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
      console.error("Email is required");
      return res.status(400).json({ error: "Email is required" });
    }

    const user = await getUserByEmail(email);
    console.log("User fetched for authentication:", user);

    if (user == null) {
      console.error("No user found for email:", email);
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

    console.log("Generated authentication options:", options);

    res.cookie(
      "authInfo",
      JSON.stringify({
        userId: user._id, // Use _id from MongoDB
        challenge: options.challenge,
      }),
      { httpOnly: true, maxAge: 60000, secure: true }
    );

    console.log("Authentication info stored in cookie:", {
      userId: user._id,
      challenge: options.challenge,
    });

    res.json(options);
  } catch (error) {
    console.error("Error in init-auth:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Test endpoint
app.get("/test", (req, res) => {
  console.log("Test endpoint called");
  res.json({ message: "Server is running successfully!" });
});

app.post("/verify-auth", async (req, res) => {
  try {
    const authInfo = JSON.parse(req.cookies.authInfo);

    console.log("verify-auth called with authInfo:", authInfo);
    console.log("Request body received for verification:", req.body);

    if (!authInfo) {
      console.error("Authentication info not found in cookies");
      return res.status(400).json({ error: "Authentication info not found" });
    }

    const user = await getUserById(authInfo.userId);
    console.log("User fetched for verification:", user);

    if (user == null || user.passKey.id != req.body.id) {
      console.error("Invalid user or passKey ID mismatch:", { user, bodyId: req.body.id });
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
      console.log("User counter updated:", user._id);

      res.clearCookie("authInfo");
      return res.json({ verified: verification.verified });
    } else {
      console.error("Verification failed:", verification);
      return res.status(400).json({ verified: false, error: "Verification failed" });
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

