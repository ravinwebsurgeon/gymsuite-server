const express = require("express");
const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");
const { json } = require("body-parser");
require("dotenv").config();

const app = express();

// Allowed origins for CORS
const allowedOrigins = [
  "http://13.54.66.195",
  "http://localhost:3000",
  "https://www.gymsuite.ai",
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
const MODAL_TABLE_NAME = process.env.MODAL_TABLE_NAME;
const EMAIL_CLUB_INDEX = process.env.EMAIL_CLUB_INDEX;

// Create a new router for API routes
const apiRouter = express.Router();

// Define the routes using the router
apiRouter.get("/", (req, res) => {
  res.json({ message: "Testing Work" });
});

apiRouter.post("/signup", async (req, res) => {
  const { email, name, password, isGoogleUser } = req.body;
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
    return res
      .status(400)
      .json({ message: "User already exists", user: existingUser.Items[0] });
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
      name,
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
  if (foundUser.isGoogleUser) {
    return res.status(400).json({
      message:
        "Your account is connected to Google - use the Google button to login ",
    });
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

  res.json({ token, name: foundUser.name });
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

// Get Dynamo DB (Data Model)
apiRouter.get("/data-model", async (req, res) => {
  const ID = 1;
  const { email, Club, Date_Time } = req.query;
  const dateTime = formatDate(Date_Time);

  if (!ID) {
    return res.status(400).json({ message: "userId is required" });
  }
  try {
    const data = await dynamoDB
      .query({
        TableName: MODAL_TABLE_NAME,
        IndexName: EMAIL_CLUB_INDEX,
        KeyConditionExpression: "User_Email = :User_Email AND :Club = Club",
        FilterExpression: "contains(Date_Time, :monthYear)",
        ExpressionAttributeValues: {
          ":User_Email": email,
          ":monthYear": dateTime,
          ":Club": Club,
        },
      })
      .promise();
    const sortedDataDesc = data?.Items.sort((a, b) => {
      const dateA = new Date(a.Date_Time.split("/").reverse().join(" "));
      const dateB = new Date(b.Date_Time.split("/").reverse().join(" "));
      return dateB - dateA;
    });

    if (!data.Items || data.Items.length === 0) {
      return res.status(400).json({ message: "Values Not Found" });
    }

    res.json({ data: sortedDataDesc[0] });
  } catch (error) {
    console.log(error);

    res.status(500).json({ message: "Internal Server Error" });
  }
});

apiRouter.post("/update-user", async (req, res) => {
  const {
    email,
    clubwise_URL,
    business_name,
    logo,
    First_Name,
    Last_Name,
    phone,
    password,
  } = req.body;
  try {
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

    if (user.Items.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const foundUser = user.Items[0];
    const hashedPassword = await bcrypt.hash(password, 10);
    const userUpdated = await dynamoDB
      .update({
        TableName: TABLE_NAME,
        Key: { email: email },
        UpdateExpression:
          "SET #clubwise_URL = :clubwise_URL, #business_name = :business_name, #logo = :logo, #First_Name = :First_Name, #Last_Name = :Last_Name, #phone = :phone, #password = :password",
        ExpressionAttributeNames: {
          "#clubwise_URL": "Clubwise_URL",
          "#business_name": "Business_name",
          "#logo": "Logo",
          "#First_Name": "First_Name",
          "#Last_Name": "Last_Name",
          "#phone": "phone",
          "#password": "password",
        },
        ExpressionAttributeValues: {
          ":clubwise_URL": clubwise_URL,
          ":business_name": business_name,
          ":logo": logo,
          ":First_Name": First_Name,
          ":Last_Name": Last_Name,
          ":phone": phone,
          ":password": hashedPassword,
        },
        ReturnValues: "ALL_NEW",
      })
      .promise();

    res.status(200).json({ data: userUpdated.Attributes });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

apiRouter.post("/sources", async (req, res) => {
  const { sources, ID } = req.body;
  const json = JSON.parse(sources);
  try {
    const userUpdated = await dynamoDB
      .update({
        TableName: MODAL_TABLE_NAME,
        Key: { ID: ID },
        UpdateExpression: "SET #ls1 = :ls1,  #ls2 = :ls2,  #ls3 = :ls3",
        ExpressionAttributeNames: {
          "#ls1": "LEAD SOURCES 1",
          "#ls2": "LEAD SOURCES 2",
          "#ls3": "LEAD SOURCES 3",
        },
        ExpressionAttributeValues: {
          ":ls1": json.first,
          ":ls2": json.second,
          ":ls3": json.third,
        },
        ReturnValues: "ALL_NEW",
      })
      .promise();

    res.status(200).json({ data: userUpdated.Attributes });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

apiRouter.post("/strategic-focus", async (req, res) => {
  const { data, ID } = req.body;
  const json = JSON.parse(data);
  try {
    const userUpdated = await dynamoDB
      .update({
        TableName: MODAL_TABLE_NAME,
        Key: { ID: ID },
        UpdateExpression: "SET #ls1 = :ls1,  #ls2 = :ls2,  #ls3 = :ls3",
        ExpressionAttributeNames: {
          "#ls1": "STRATEGIC FOCUS 1",
          "#ls2": "STRATEGIC FOCUS 2",
          "#ls3": "STRATEGIC FOCUS 3",
        },
        ExpressionAttributeValues: {
          ":ls1": json.first,
          ":ls2": json.second,
          ":ls3": json.third,
        },
        ReturnValues: "ALL_NEW",
      })
      .promise();

    res.status(200).json({ data: userUpdated.Attributes });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

apiRouter.post("/objections", async (req, res) => {
  const { data, ID } = req.body;
  const json = JSON.parse(data);
  try {
    const userUpdated = await dynamoDB
      .update({
        TableName: MODAL_TABLE_NAME,
        Key: { ID: ID },
        UpdateExpression: "SET #ls1 = :ls1,  #ls2 = :ls2,  #ls3 = :ls3",
        ExpressionAttributeNames: {
          "#ls1": "OBJECTIONS 1",
          "#ls2": "OBJECTIONS 2",
          "#ls3": "OBJECTIONS 3",
        },
        ExpressionAttributeValues: {
          ":ls1": json.objection1,
          ":ls2": json.objection2,
          ":ls3": json.objection3,
        },
        ReturnValues: "ALL_NEW",
      })
      .promise();

    res.status(200).json({ data: userUpdated.Attributes });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

apiRouter.post("/complaints", async (req, res) => {
  const { data, ID } = req.body;
  const json = JSON.parse(data);
  try {
    const userUpdated = await dynamoDB
      .update({
        TableName: MODAL_TABLE_NAME,
        Key: { ID: ID },
        UpdateExpression: "SET #ls1 = :ls1,  #ls2 = :ls2,  #ls3 = :ls3",
        ExpressionAttributeNames: {
          "#ls1": "COMPLAINTS 1",
          "#ls2": "COMPLAINTS 2",
          "#ls3": "COMPLAINTS 3",
        },
        ExpressionAttributeValues: {
          ":ls1": json.complaint1,
          ":ls2": json.complaint2,
          ":ls3": json.complaint3,
        },
        ReturnValues: "ALL_NEW",
      })
      .promise();

    res.status(200).json({ data: userUpdated.Attributes });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

apiRouter.post("/settings", async (req, res) => {
  const { email, CRM_API_Key, CRM_Username, CRM_Password } = req.body;
  const hashedPassword = await bcrypt.hash(CRM_Password, 10);

  try {
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

    if (user.Items.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const foundUser = user.Items[0];

    const userUpdated = await dynamoDB
      .update({
        TableName: TABLE_NAME,
        Key: { email: email },
        UpdateExpression:
          "SET #CRM_API_Key = :CRM_API_Key, #CRM_Username = :CRM_Username, #CRM_Password = :CRM_Password",
        ExpressionAttributeNames: {
          "#CRM_API_Key": "CRM_API_Key",
          "#CRM_Username": "CRM_Username",
          "#CRM_Password": "CRM_Password",
        },
        ExpressionAttributeValues: {
          ":CRM_API_Key": CRM_API_Key,
          ":CRM_Username": CRM_Username,
          ":CRM_Password": hashedPassword,
        },
        ReturnValues: "ALL_NEW",
      })
      .promise();

    res.status(200).json({ data: userUpdated.Attributes });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

apiRouter.post("/user-data", async (req, res) => {
  const { email } = req.body;
  try {
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
    res.status(200).json({ data: user.Items[0] });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

apiRouter.get("/get-clubs", async (req, res) => {
  const { email } = req.query;
  try {
    const rows = await dynamoDB
      .query({
        TableName: MODAL_TABLE_NAME,
        IndexName: EMAIL_INDEX,
        KeyConditionExpression: "User_Email = :User_Email",
        ExpressionAttributeValues: {
          ":User_Email": email,
        },
      })
      .promise();
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
    const clubs = [];
    rows.Items.map((item) => {
      if (!clubs.some((club) => club.label === item.Club)) {
        clubs.push({ label: item.Club, value: item.Club });
      }
    });

    res.status(200).json({ clubs: clubs, user: user });
  } catch (error) {
    console.error("Error fetching clubs:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

apiRouter.post("/update-data", async (req, res) => {
  let { data, email } = req.body;
  try { 
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
    const getLatest = await dynamoDB
      .scan({
        TableName: MODAL_TABLE_NAME,
      })
      .promise();
    data.ID = getLatest.ScannedCount + 3;
    const addingItem = await dynamoDB
      .put({
        TableName: MODAL_TABLE_NAME,
        Item: data,
      })
      .promise();
    const getRow = await dynamoDB
      .query({
        TableName: MODAL_TABLE_NAME,
        KeyConditionExpression: "ID = :ID",
        ExpressionAttributeValues: {
          ":ID": data.ID,
        },
      })
      .promise();

    res.status(200).json({ data: getRow?.Items[0] });    
  } else {
    res.status(500).json({ error: "Your don't have permissions" });
  }
} catch (error) {
  console.error("Error fetching clubs:", error);
  res.status(500).json({ error: "Internal Server Error" });
}
});


apiRouter.post("/prev-data", async (req, res) => {
  let { ID } = req.body;
  try {
    const items = await dynamoDB
      .query({
        TableName: MODAL_TABLE_NAME,
        KeyConditionExpression: "ID = :ID",
        ExpressionAttributeValues: {
          ":ID": ID,
        },
      })
      .promise();

    res.status(200).json({ data: items?.Items[0] });    
  } catch (error) {
    console.error("Error fetching clubs:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
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

const formatDate = (dateString) => {
  const date = new Date(dateString);

  const day = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = date.getFullYear();

  return `${month}/${year}`;
};
