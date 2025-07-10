import express from "express";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();
import Stripe from "stripe";
import jwt from "jsonwebtoken";
import { MongoClient, ServerApiVersion } from "mongodb";
// Assuming you have Express app setup and Stripe installed
const stripe = new Stripe(`${process.env.STRIPE_SECRET}`);

const app = express();
const PORT = process.env.PORT || 5000;

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://soulmate-here.surge.sh",
      "https://matrimony-c85da.web.app/",
    ],
    credentials: true,
  })
);

app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@skillstack.6gwde6m.mongodb.net/?retryWrites=true&w=majority&appName=skillStack`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db; // <-- This will hold your DB instance

// JWT verification middleware
function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Forbidden" });
    req.user = decoded;
    next();
  });
}

async function run() {
  try {
    await client.connect();
    db = client.db("matrimonyDB"); // <-- Assign DB here once

    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. Successfully connected to MongoDB!");

    // Root route
    app.get("/", (req, res) => {
      res.send("Matrimony Backend Running");
    });

    // Register user (no password, using Firebase uid)
    app.post("/api/register", async (req, res) => {
      try {
        const { uid, name, email, photoURL } = req.body;
        if (!uid || !email)
          return res.status(400).json({ message: "UID and Email required" });

        const usersCollection = db.collection("users");
        const existingUser = await usersCollection.findOne({ uid });

        if (existingUser) {
          // User exists — return token
          const token = jwt.sign(
            {
              uid: existingUser.uid,
              email: existingUser.email,
              role: existingUser.role || "user",
            },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
          );
          return res
            .status(200)
            .json({ message: "User already exists", token });
        }

        await usersCollection.insertOne({
          uid,
          name,
          email,
          photoURL,
          role: "user",
          createdAt: new Date(),
        });

        const token = jwt.sign(
          { uid, email, role: "user" },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.status(201).json({ message: "User registered", token });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Login user (via uid from Firebase)
    app.post("/api/login", async (req, res) => {
      try {
        const { uid } = req.body;

        if (!uid) return res.status(400).json({ message: "UID required" });

        const usersCollection = db.collection("users");
        const user = await usersCollection.findOne({ uid });

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        // Generate JWT
        const token = jwt.sign(
          { uid: user.uid, email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        // Prepare a clean user object (remove Mongo _id and Date object structure)
        const { _id, createdAt, ...cleanUser } = user;

        res.json({
          message: "User logged in",
          token,
          user: cleanUser, // 👈 send cleaned user object
          success: true,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // GET
    app.get("/api/status/:uid", verifyJWT, async (req, res) => {
      try {
        const uid = req.params.uid;
        const user = await db.collection("users").findOne({ uid });

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        // Example: assuming premium status is stored in user.status or user.isPremium
        const status = user.status || (user.isPremium ? "approved" : "pending");

        return res.json({ status });
      } catch (error) {
        console.error("Error fetching user status:", error);
        return res.status(500).json({ message: "Failed to fetch user status" });
      }
    });

    // Helper to get next biodataId (auto-increment)
    async function getNextBiodataId() {
      const biodataCollection = db.collection("biodatas");
      const lastBiodata = await biodataCollection
        .find()
        .sort({ biodataId: -1 })
        .limit(1)
        .toArray();
      return lastBiodata.length === 0 ? 1 : lastBiodata[0].biodataId + 1;
    }

    // Create or edit biodata (user can only have one)
    app.post("/api/biodata", verifyJWT, async (req, res) => {
      try {
        const biodataCollection = db.collection("biodatas");
        const userId = req.user.uid; // Now req.user will be defined
        const biodataData = req.body;

        // Ensure user is only editing their own biodata
        if (biodataData.contactEmail !== req.user.email) {
          return res
            .status(403)
            .json({ message: "Unauthorized to create/edit this biodata" });
        }

        const existing = await biodataCollection.findOne({ uid: userId });

        if (existing) {
          await biodataCollection.updateOne(
            { uid: userId },
            { $set: biodataData }
          );
          return res.json({
            success: true,
            message: "Biodata updated successfully",
          });
        } else {
          const newId = await getNextBiodataId();
          biodataData.uid = userId;
          biodataData.biodataId = newId;
          biodataData.createdAt = new Date();
          biodataData.premium = false; // default
          await biodataCollection.insertOne(biodataData);
          return res.status(201).json({
            success: true,
            message: "Biodata created successfully",
            biodataId: newId,
          });
        }
      } catch (error) {
        res.status(500).json({ success: false, message: error.message });
      }
    });

    // Get single biodata details by biodataId (private route)
    // assuming you have your verifyJWT middleware set up
    app.get("/api/biodata/:biodataId", verifyJWT, async (req, res) => {
      try {
        const rawId = req.params.biodataId;
        const parsedId = parseInt(rawId);

        const query = !isNaN(parsedId)
          ? { biodataId: parsedId }
          : { biodataId: rawId };
        const biodataCollection = db.collection("biodatas");
        const biodata = await biodataCollection.findOne(query);

        if (!biodata)
          return res.status(404).json({ message: "Biodata not found" });

        const userId = req.user.uid;
        const userEmail = req.user.email;

        const isOwner = biodata.uid === userId;
        const isPremium = biodata.premium === true;

        // Check if user has an approved contact request for this biodata
        const contactRequestCollection = db.collection("contactRequests");
        const approvedRequest = await contactRequestCollection.findOne({
          biodataId: biodata.biodataId,
          userEmail: userEmail,
          status: "approved",
        });

        // Only show sensitive contact info if owner, premium, or has approved request
        if (!isOwner && !isPremium && !approvedRequest) {
          delete biodata.contactEmail;
          delete biodata.mobile;
        }

        res.json({ biodata });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Get biodata for logged-in user by email (private)
    app.get("/api/my-biodata", verifyJWT, async (req, res) => {
      try {
        const email = req.query.email;
        if (req.user.email !== email) {
          return res.status(403).json({ message: "Forbidden access" });
        }

        const biodata = await db
          .collection("biodatas")
          .findOne({ contactEmail: email });
        if (!biodata)
          return res.json({ success: false, message: "No biodata found" });

        res.json({ success: true, biodata });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Request to become premium biodata
    app.post("/api/request-premium", verifyJWT, async (req, res) => {
      try {
        const { biodataId } = req.body;
        const email = req.user.email;
        const uid = req.user.uid;

        const premiumRequestsCollection = db.collection("premiumRequests");

        const existing = await premiumRequestsCollection.findOne({ biodataId });
        if (existing)
          return res.json({ success: false, message: "Already requested" });

        // ✅ Fetch user's name from users collection
        const user = await db.collection("users").findOne({ uid });

        const newRequest = {
          biodataId,
          uid,
          email,
          name: user?.name || "Unknown", // ✅ Save name here
          status: "pending",
          createdAt: new Date(),
        };

        const result = await premiumRequestsCollection.insertOne(newRequest);

        res.json({ success: true, insertedId: result.insertedId });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Admin approve premium biodata
    app.patch("/api/admin/approve-premium", verifyJWT, async (req, res) => {
      try {
        if (req.user.role !== "admin")
          return res.status(403).json({ message: "Access denied" });

        const { biodataId } = req.body;
        const biodatasCollection = db.collection("biodatas");
        const premiumRequestsCollection = db.collection("premiumRequests");

        await biodatasCollection.updateOne(
          { biodataId },
          { $set: { premium: true } }
        );
        await premiumRequestsCollection.updateOne(
          { biodataId },
          { $set: { status: "approved" } }
        );

        res.json({ success: true, message: "Biodata marked as premium" });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Edit biodata
    app.patch("/api/biodata", verifyJWT, async (req, res) => {
      try {
        const updatedData = req.body;
        if (req.user.email !== updatedData.contactEmail) {
          return res.status(403).json({ message: "Unauthorized" });
        }
        const result = await db
          .collection("biodatas")
          .updateOne(
            { contactEmail: updatedData.contactEmail },
            { $set: updatedData }
          );
        res.json({ success: true, modifiedCount: result.modifiedCount });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Get list of biodatas with filters and pagination (public)
    app.get("/api/biodatas", async (req, res) => {
      try {
        const {
          biodataType,
          division,
          ageMin,
          ageMax,
          sortByAge,
          page = 1,
          limit = 20,
        } = req.query;

        const query = {};
        if (biodataType) query.biodataType = biodataType;
        if (division) query.permanentDivision = division;

        if (ageMin || ageMax) {
          query.age = {};
          if (ageMin) query.age.$gte = parseInt(ageMin);
          if (ageMax) query.age.$lte = parseInt(ageMax);
        }

        const sort = {};
        if (sortByAge === "asc") sort.age = 1;
        else if (sortByAge === "desc") sort.age = -1;

        const skip = (parseInt(page) - 1) * parseInt(limit);

        const biodataCollection = db.collection("biodatas");
        const total = await biodataCollection.countDocuments(query);

        const biodatas = await biodataCollection
          .find(query)
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        res.json({
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          biodatas,
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // POST /api/favourites
    app.post("/api/favourites", verifyJWT, async (req, res) => {
      try {
        const { biodataId } = req.body;
        const uid = req.user.uid;

        if (!biodataId)
          return res.status(400).json({ message: "Missing biodataId" });

        const collection = db.collection("favourites");

        // prevent duplicate
        const exists = await collection.findOne({ uid, biodataId });
        if (exists)
          return res
            .status(409)
            .json({ message: "Already added to favourites" });

        await collection.insertOne({ uid, biodataId, addedAt: new Date() });
        res.json({ success: true });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // GET /api/favourites/check?userId=uid&biodataId=1
    app.get("/api/favourites/check/:biodataId", verifyJWT, async (req, res) => {
      const userId = req.user.uid; // from JWT
      const { biodataId } = req.params;

      try {
        const exists = await favourites.findOne({
          uid: userId,
          biodataId: parseInt(biodataId),
        });
        res.json({ isFavorite: !!exists });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to check favourite status." });
      }
    });

    // GET /api/my-favourites
    app.get("/api/my-favourites", verifyJWT, async (req, res) => {
      try {
        const uid = req.user.uid;
        const favCollection = db.collection("favourites");
        const biodataCollection = db.collection("biodatas");

        const favourites = await favCollection.find({ uid }).toArray();

        // Fetch full biodata for each favourite
        const detailedFavourites = await Promise.all(
          favourites.map(async (fav) => {
            const biodata = await biodataCollection.findOne({
              biodataId: fav.biodataId,
            });
            return biodata;
          })
        );

        res.json({ success: true, favourites: detailedFavourites });
      } catch (error) {
        console.error("Fetch favourites error:", error);
        res.status(500).json({ message: "Failed to fetch favourites." });
      }
    });

    // POST /api/request-contact
    app.get("/api/request-contact", verifyJWT, async (req, res) => {
      try {
        const contactRequests = await db
          .collection("contactRequests")
          .aggregate([
            {
              $lookup: {
                from: "biodatas",
                localField: "biodataId",
                foreignField: "biodataId",
                as: "biodataInfo",
              },
            },
            {
              $unwind: {
                path: "$biodataInfo",
                preserveNullAndEmptyArrays: true,
              },
            },
            {
              $project: {
                uid: 1,
                biodataId: 1,
                requestedAt: 1,
                status: 1,
                biodataType: "$biodataInfo.biodataType",
              },
            },
          ])
          .toArray();

        res.json({ requests: contactRequests });
      } catch (error) {
        console.error("Error fetching contact requests:", error);
        res.status(500).json({ message: "Server error" });
      }
    });

    // GET /api/my-contact-requests
    // Middleware must decode JWT and attach `req.user.uid`
    app.get("/api/my-contact-requests", verifyJWT, async (req, res) => {
      try {
        const uid = req.user.uid;

        const requests = await db
          .collection("contactRequests")
          .find({ uid }) // 🔥 Make sure your documents have "uid" field
          .toArray();

        res.json({ requests });
      } catch (error) {
        console.error("Error fetching contact requests:", error);
        res.status(500).json({ message: "Failed to fetch requests." });
      }
    });

    app.post("/api/success-story", verifyJWT, async (req, res) => {
      try {
        const { selfBiodataId, partnerBiodataId, image, story } = req.body;

        if (!selfBiodataId || !partnerBiodataId || !image || !story) {
          return res.status(400).json({ message: "All fields are required" });
        }

        const successStory = {
          selfBiodataId: parseInt(selfBiodataId),
          partnerBiodataId: parseInt(partnerBiodataId),
          image,
          story,
          createdAt: new Date(),
          email: req.user.email,
        };

        const result = await db
          .collection("successStories")
          .insertOne(successStory);
        res.json({ success: true, insertedId: result.insertedId });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    app.post("/api/create-payment-intent", verifyJWT, async (req, res) => {
      try {
        const { amount } = req.body;

        if (!amount || amount < 1) {
          return res.status(400).json({ message: "Invalid amount" });
        }

        const paymentIntent = await stripe.paymentIntents.create({
          amount,
          currency: "usd",
          metadata: { integration_check: "accept_a_payment" },
        });

        res.json({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        console.error("Stripe create payment intent error:", error);
        res.status(500).json({
          message: error.message || "Failed to create payment intent",
        });
      }
    });

    app.post("/api/request-contact", verifyJWT, async (req, res) => {
      try {
        const { biodataId, userEmail } = req.body;

        if (!biodataId || !userEmail) {
          return res.status(400).json({ message: "Missing required fields" });
        }

        // 🔍 Fetch name from the logged-in user
        const user = await db
          .collection("users")
          .findOne({ uid: req.user.uid });

        // Create a new contact request object
        const newRequest = {
          uid: req.user.uid,
          biodataId,
          userEmail,
          name: user?.name || "Unknown",
          status: "pending",
          requestedAt: new Date(),
        };

        const result = await db
          .collection("contactRequests")
          .insertOne(newRequest);

        if (result.insertedId) {
          res.json({ success: true, message: "Contact request submitted" });
        } else {
          res.status(500).json({ message: "Failed to save contact request" });
        }
      } catch (error) {
        console.error("Error saving contact request:", error);
        res.status(500).json({ message: error.message || "Server error" });
      }
    });

    app.get("/api/admin/stats", async (req, res) => {
      try {
        const totalBiodata = await db.collection("biodatas").countDocuments();
        const maleCount = await db
          .collection("biodatas")
          .countDocuments({ biodataType: "Male" });
        const femaleCount = await db
          .collection("biodatas")
          .countDocuments({ biodataType: "Female" });
        const premiumCount = await db
          .collection("biodatas")
          .countDocuments({ isPremium: true });

        const requests = await db
          .collection("contactRequests")
          .find({ status: "approved" })
          .toArray();
        const totalRevenue = requests.length * 5; // $5 per request

        res.json({
          totalBiodata,
          maleCount,
          femaleCount,
          premiumCount,
          totalRevenue,
        });
      } catch (err) {
        res.status(500).json({ message: "Failed to fetch stats" });
      }
    });

    app.get("/api/users", async (req, res) => {
      try {
        const search = req.query.search || "";
        const users = await db
          .collection("users")
          .find({ name: { $regex: search, $options: "i" } })
          .toArray();
        res.json(users);
      } catch (err) {
        res.status(500).json({ message: "Failed to fetch users." });
      }
    });

    app.patch("/api/users/role", async (req, res) => {
      try {
        const { email, role } = req.body;

        if (!email || !["admin", "premium"].includes(role)) {
          return res.status(400).json({ message: "Invalid request." });
        }

        const update =
          role === "admin" ? { role: "admin" } : { isPremium: true };

        const result = await db
          .collection("users")
          .updateOne({ email }, { $set: update });

        res.json({ success: true, modifiedCount: result.modifiedCount });
      } catch (err) {
        res.status(500).json({ message: "Failed to update user role." });
      }
    });

    app.get("/api/premium-requests", async (req, res) => {
      try {
        const requests = await db
          .collection("premiumRequests")
          .find({})
          .toArray();
        res.json(requests);
      } catch (err) {
        res.status(500).json({ message: "Failed to fetch requests." });
      }
    });

    app.patch("/api/approve-premium", async (req, res) => {
      try {
        const { email, biodataId } = req.body;

        if (!email || !biodataId) {
          return res.status(400).json({ message: "Missing required fields." });
        }

        // Update biodata to premium
        await db.collection("biodatas").updateOne(
          { biodataId }, // keep as string
          { $set: { isPremium: true } }
        );

        // Update user to premium (optional)
        await db
          .collection("users")
          .updateOne({ email }, { $set: { isPremium: true } });

        // ✅ Fix: Match using string biodataId
        await db
          .collection("premiumRequests")
          .updateOne(
            { email, biodataId },
            { $set: { status: "approved", isPremium: true } }
          );

        res.json({ success: true });
      } catch (err) {
        res.status(500).json({ message: "Failed to approve premium." });
      }
    });

    app.get("/api/premiumRequests/status/:userId", async (req, res) => {
      try {
        const userId = req.params.userId;

        if (!userId) {
          return res.status(400).json({ message: "User ID is required." });
        }

        const request = await db
          .collection("premiumRequests")
          .findOne({ uid: userId });

        if (!request) {
          return res.json({ status: "none" }); // no request found
        }

        res.json({ status: request.status || "pending" });
      } catch (err) {
        console.error("Error fetching premium request status:", err);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.get("/api/contact-requests", async (req, res) => {
      try {
        const requests = await db
          .collection("contactRequests")
          .aggregate([
            {
              $lookup: {
                from: "users",
                localField: "uid",
                foreignField: "uid",
                as: "userInfo",
              },
            },
            {
              $unwind: {
                path: "$userInfo",
                preserveNullAndEmptyArrays: true,
              },
            },
            {
              $project: {
                _id: 1,
                uid: 1,
                biodataId: 1,
                requestedAt: 1,
                status: 1,
                name: {
                  $cond: [
                    { $ifNull: ["$userInfo.name", false] },
                    "$userInfo.name",
                    "Unknown",
                  ],
                },
                email: {
                  $cond: [
                    { $ifNull: ["$userInfo.email", false] },
                    "$userInfo.email",
                    "$userEmail", // fallback to userEmail from request
                  ],
                },
              },
            },
          ])
          .toArray();

        res.json(requests);
      } catch (err) {
        console.error("Error fetching contact requests:", err);
        res.status(500).json({ message: "Failed to fetch contact requests." });
      }
    });

    app.patch("/api/approve-contact", async (req, res) => {
      const { uid, biodataId } = req.body;

      try {
        const filter = {
          uid,
          biodataId: Number(biodataId),
          status: { $ne: "approved" },
        };

        const updateResult = await db
          .collection("contactRequests")
          .updateOne(filter, { $set: { status: "approved" } });

        if (updateResult.modifiedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Request not found or already approved.",
          });
        }

        res.json({ success: true });
      } catch (error) {
        console.error(error);
        res.status(500).json({
          success: false,
          message: "Failed to approve contact request.",
        });
      }
    });

    app.get("/api/success-stories", async (req, res) => {
      try {
        const stories = await db
          .collection("successStories")
          .find()
          .sort({ createdAt: -1 }) // descending order
          .toArray();

        res.json({ success: true, stories });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch success stories." });
      }
    });

    // GET /api/contact-request-status?biodataId=4&userId=jrVRLTcSsOdyNIGSlQo67p45Mnu2
    app.get("/api/contact-request-status", async (req, res) => {
      const { biodataId, userId } = req.query;

      if (!biodataId || !userId) {
        return res
          .status(400)
          .json({ approved: false, message: "Missing biodataId or userId" });
      }

      try {
        // Normalize biodataId as number
        const bioIdNum = Number(biodataId);

        // Query contactRequests collection for approved status matching userId and biodataId
        const request = await db.collection("contactRequests").findOne({
          uid: userId,
          biodataId: bioIdNum,
          status: "approved",
        });

        if (request) {
          return res.json({ approved: true });
        } else {
          return res.json({ approved: false });
        }
      } catch (error) {
        console.error(error);
        return res
          .status(500)
          .json({ approved: false, message: "Server error" });
      }
    });

    app.get("/api/counter-stats", async (req, res) => {
      try {
        const total = await db.collection("biodatas").countDocuments();
        const girls = await db
          .collection("biodatas")
          .countDocuments({ biodataType: "Female" });
        const boys = await db
          .collection("biodatas")
          .countDocuments({ biodataType: "Male" });
        const marriages = await db
          .collection("successStories")
          .countDocuments();

        res.json({
          totalBiodata: total,
          totalGirls: girls,
          totalBoys: boys,
          totalMarriages: marriages,
        });
      } catch (err) {
        console.error("Counter stats error:", err);
        res.status(500).json({ message: "Failed to load stats" });
      }
    });

    // Start server
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error(err);
  }
}

run().catch(console.dir);
