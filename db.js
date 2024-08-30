const mongoose = require("mongoose");

mongoose.connect("mongodb+srv://chan:LaslTTtKYT8WqDvJ@2day.zfio7.mongodb.net/2day?retryWrites=true&w=majority", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

const passKeySchema = new mongoose.Schema({
  id: String,
  publicKey: Buffer, // Store as Buffer to ensure proper format
  counter: Number,
  deviceType: String,
  backedUp: Boolean,
  transports: [String],
});

const userSchema = new mongoose.Schema({
  _id: String, // Use String if you want to set your own ID
  email: { type: String, unique: true },
  firstName: String,
  lastName: String,
  dob: Date,
  passKey: passKeySchema,
});

const User = mongoose.model("User", userSchema);

async function getUserByEmail(email) {
  return await User.findOne({ email });
}

async function getUserById(id) {
  return await User.findById(id);
}

async function createUser(id, email, passKey) {
  const user = new User({
    _id: id,
    email,
    firstName: passKey.firstName,
    lastName: passKey.lastName,
    dob: passKey.dob,
    passKey: {
      id: passKey.id,
      publicKey: Buffer.from(passKey.publicKey), // Store publicKey as Buffer
      counter: passKey.counter,
      deviceType: passKey.deviceType,
      backedUp: passKey.backedUp,
      transports: passKey.transports,
    },
  });
  await user.save();
}

async function updateUserCounter(id, counter) {
  await User.updateOne(
    { _id: id, "passKey.id": id },
    { $set: { "passKey.counter": counter } }
  );
}

module.exports = {
  getUserByEmail,
  getUserById,
  createUser,
  updateUserCounter,
};
