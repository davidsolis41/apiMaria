import express, { Request, Response } from "express";
import cors from "cors";
import morgan from "morgan";
import authRoutes from "./routes/authRoutes";
import fileUpload from "express-fileupload";
import sequelize from "./config/sequelize";

//initializations

const app = express();

require("dotenv").config();

require("./databases/mongo");
require("./databases/maria");
require("./models/maria/associations");
sequelize.sync();

//settings

app.set("port", process.env.PORT);

//middlewares
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: false }));
app.use(
  fileUpload({
    useTempFiles: true,
    tempFileDir: "/tmp/",
  })
);

//routes

app.get("/", (req: Request, res: Response) => {
  res.status(200).json({ msg: "bienvenido al api" });
});

app.use(authRoutes);

// exportaciones

export default app;
