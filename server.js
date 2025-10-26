import app from "./src/app.js";
import { connect } from "./src/broker/rabbit.js";
import config from "./src/config/config.js";
import connectDB from "./src/db/db.js";



connectDB()
connect()

if (process.env.NODE_ENV === "development") {
  console.log("🧑‍💻 Running in development mode");
} else {
  console.log("🚀 Running in production mode");
}

const PORT = config.PORT || 4000


app.listen(PORT,()=>{
    console.log(`🔥Auth server is connect on ${PORT}`)
})




