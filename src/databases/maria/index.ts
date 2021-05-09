import sequelize from "../../config/sequelize";

async function connectionDB() {
  try {
    await sequelize.authenticate();
    console.log("Conexion a mariaDB establecida exitosamente");
  } catch (error) {
    console.log("Ocurrio un error al conectarse a mariaDB: ", error);
  }
}

connectionDB();
