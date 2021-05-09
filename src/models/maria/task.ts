import { DataTypes, Model } from "sequelize";
import sequelize from "../../config/sequelize";

class Task extends Model {}
Task.init(
  {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
      allowNull: false,
    },
    nombre: {
      type: DataTypes.STRING,
    },
    idUsuario: {
      type: DataTypes.INTEGER,
    },
  },
  {
    sequelize, // We need to pass the connection instance
    modelName: "Task", // We need to choose the model name
  }
);

export default Task;
