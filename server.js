// const dotenv = require("dotenv");
// dotenv.config({ path: "./config.env" });
const mongoose = require("mongoose");
const app = require("./index");
const { port, DB_URL } = process.env;

mongoose
  .connect(DB_URL)
  .then(() => console.log("connected"))
  .catch((err) => console.log(err));

app.listen(port|| process.env.PORT, () => {
  console.log("server is up and running");
});
