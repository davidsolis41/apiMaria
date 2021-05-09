import Usuario from "./usuario";
import Task from "./task";

Usuario.hasMany(Task);
Task.belongsTo(Usuario);
