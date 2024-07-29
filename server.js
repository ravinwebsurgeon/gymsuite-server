const express = require("express");
const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");
require("dotenv").config();
 
const app = express();
 
// Allowed origins for CORS
const allowedOrigins = [
  "http://13.54.66.195",
  "https://gymsuite.ai",
];
 
const corsOptions = {
  origin: (origin, callback) => {
    if (allowedOrigins.includes(origin) || !origin) {
      callback(null, true);
    } else {
      callback(new Error(`This IP ${origin} is not allowed by CORS`));
    }
  },
};
 
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
 
// Configure AWS
AWS.config.update({
  region: "ap-southeast-2",
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});
 
const dynamoDB = new AWS.DynamoDB.DocumentClient();
const TABLE_NAME = process.env.TABLE_NAME;
const EMAIL_INDEX = process.env.EMAIL_INDEX;
const JWT_SECRET = process.env.JWT_SECRET;
 
// Create a new router for API routes
const apiRouter = express.Router();
 
// Define the routes using the router
apiRouter.get("/", (req, res) => {
  res.json({ message: "Testing Work" });
});
 
apiRouter.post("/signup", async (req, res) => {
  const { email, password, isGoogleUser } = req.body;
 
  // Check if user already exists using the secondary index
  const existingUser = await dynamoDB
    .query({
      TableName: TABLE_NAME,
      IndexName: EMAIL_INDEX,
      KeyConditionExpression: "email = :email",
      ExpressionAttributeValues: {
        ":email": email,
      },
    })
    .promise();
 
  if (existingUser.Items && existingUser.Items.length > 0) {
    return res.status(400).json({ message: "User already exists" });
  }
 

 
  // Create new user
  let newUser;
  if (isGoogleUser) {
    newUser = {
      userId: uuidv4(),
      email,
      isGoogleUser: isGoogleUser,
    };
 
  } else {
      // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);
    newUser = {
      userId: uuidv4(),
      email,
      password: hashedPassword,
    };
  }
 
  await dynamoDB
    .put({
      TableName: TABLE_NAME,
      Item: newUser,
    })
    .promise();
 
  res.status(201).json({ message: "User created successfully" });
});
 
apiRouter.post("/signin", async (req, res) => {
  const { email, password } = req.body;
 
  // Find user using the secondary index
  const user = await dynamoDB
    .query({
      TableName: TABLE_NAME,
      IndexName: EMAIL_INDEX,
      KeyConditionExpression: "email = :email",
      ExpressionAttributeValues: {
        ":email": email,
      },
    })
    .promise();
 
  if (!user.Items || user.Items.length === 0) {
    return res.status(400).json({ message: "User not found" });
  }
 
  const foundUser = user.Items[0];
 console.log(foundUser,"***************");
 if(foundUser.isGoogleUser){
  return res.status(400).json({message:"Your account is connected to Google - use the Google button to login "})
 }
  // Check password
  const isPasswordValid = await bcrypt.compare(password, foundUser.password);
 
  if (!isPasswordValid) {
    return res.status(400).json({ message: "Invalid password" });
  }
 
  // Generate JWT token
  const token = jwt.sign(
    { userId: foundUser.userId, email: foundUser.email },
    JWT_SECRET,
    { expiresIn: "1h" }
  );
 
  res.json({ token });
});
 
apiRouter.post("/forget-password", async (req, res) => {
  const { email } = req.body;
 
  // Find user using the secondary index
  const user = await dynamoDB
    .query({
      TableName: TABLE_NAME,
      IndexName: EMAIL_INDEX,
      KeyConditionExpression: "email = :email",
      ExpressionAttributeValues: {
        ":email": email,
      },
    })
    .promise();
 
  if (!user.Items || user.Items.length === 0) {
    return res.status(400).json({ message: "User not found" });
  }
 
  const foundUser = user.Items[0];
  // Generate reset token
  const resetToken = uuidv4();
  const resetTokenExpiry = Date.now() + 3600000; // Token valid for 1 hour
 
  // Update user with reset token
  await dynamoDB
    .update({
      TableName: TABLE_NAME,
      Key: { email: foundUser.email },
      UpdateExpression:
        "SET resetToken = :resetToken, resetTokenExpiry = :resetTokenExpiry",
      ExpressionAttributeValues: {
        ":resetToken": resetToken,
        ":resetTokenExpiry": resetTokenExpiry,
      },
    })
    .promise();
 
  // In a real-world scenario, you would send an email with the reset link
  // For this example, we'll just return the token
  res.json({ message: "Password reset token generated", resetToken });
});
 
apiRouter.post("/reset-password", async (req, res) => {
  const { email, resetToken, newPassword } = req.body;
 
  // Find user using the secondary index
  const user = await dynamoDB
    .query({
      TableName: TABLE_NAME,
      IndexName: EMAIL_INDEX,
      KeyConditionExpression: "email = :email",
      ExpressionAttributeValues: {
        ":email": email,
      },
    })
    .promise();
 
  if (!user.Items || user.Items.length === 0) {
    return res.status(400).json({ message: "User not found" });
  }
 
  const foundUser = user.Items[0];
 
  // Check if reset token is valid and not expired
  if (
    foundUser.resetToken !== resetToken ||
    foundUser.resetTokenExpiry < Date.now()
  ) {
    return res.status(400).json({ message: "Invalid or expired reset token" });
  }
 
  // Hash new password
  const hashedPassword = await bcrypt.hash(newPassword, 10);
 
  // Update user with new password and remove reset token
  await dynamoDB
    .update({
      TableName: TABLE_NAME,
      Key: { userId: foundUser.userId },
      UpdateExpression:
        "SET password = :password REMOVE resetToken, resetTokenExpiry",
      ExpressionAttributeValues: {
        ":password": hashedPassword,
      },
    })
    .promise();
 
  res.json({ message: "Password reset successfully" });
});
 
// Use the API router with the base path /api/v1
app.use("/api/v1", apiRouter);
 
const PORT = process.env.PORT || 8082;
app.listen(PORT, () => {
  console.log("Running on port ", PORT);
  console.log("Routes:");
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      // only log middleware with a route
      const method = middleware.route.stack[0].method.toUpperCase();
      console.log(`${method} -> ${middleware.route.path}`);
    }
  });
});
