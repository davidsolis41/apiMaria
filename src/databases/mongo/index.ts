import mongoose, { ConnectionOptions } from "mongoose";

// inicializaciones
const dbOptions: ConnectionOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: true,
};

let URI = process.env.URI_UNO as string;

//conexion a mongo
mongoose.connect(URI.toString(), dbOptions);

const connection = mongoose.connection;

// cuando la conexion es abierta retorna esto
connection.once("open", () => {
  console.log("Conexion a MongoDB exitosa");
});

// si la conexion falla retorna esto
connection.once("error", (err) => {
  console.log("Ocurrio un error:" + err);
  process.exit(0);
});
