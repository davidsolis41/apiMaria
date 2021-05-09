import app from "../app";
import { Sequelize } from "sequelize";

let sequelize = new Sequelize("apiDB", `admin`, `12345678`, {
  host: `localhost`,
  dialect: "mariadb",
  pool: {
    max: 5,
    min: 0,
    idle: 10000,
  },
  logging: false,
});

export default sequelize;
