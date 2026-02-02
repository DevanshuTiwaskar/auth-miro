import app from "./src/app.js";
import { connectRabbit, consumeEvents } from "./src/broker/rabbit.js";
import config from "./src/config/config.js";
import connectDB from "./src/db/db.js";

const startServer = async () => {
  try {
    // Connect DB
    await connectDB();

    // Connect RabbitMQ
    await connectRabbit("auth.queue");
;
    console.log("🐰 Connected to RabbitMQ");

    // Environment log
    if (process.env.NODE_ENV === "development") {
      console.log("🧑‍💻 Running in development mode");
    } else {
      console.log("🚀 Running in production mode");
    }

    const PORT = config.PORT || 4000;

    app.listen(PORT, () => {
      console.log(`🔥 Auth server running on port ${PORT}`);
    });

    consumeEvents((data, routingKey) => {
  console.log(`📥 Received event: ${routingKey}`, data);
});


  } catch (error) {
    console.error("❌ Failed to start Auth service:", error);
    process.exit(1); // crash container → Kubernetes restarts it
  }
};

startServer();
