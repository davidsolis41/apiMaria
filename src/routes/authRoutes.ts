import { Router } from "express";
import * as authController from "../controllers/authController";
import { check } from "express-validator";
import validacionErrors from "../middlewares/validacionErrors";

let router = Router();

let comprobaciones = [
  check("email", "Debes ingresar un email valido").isEmail(),
  check("password", "La contraseña debe tener mas de 8 caracteres").isLength({
    min: 7,
    max: 100,
  }),
  validacionErrors,
];

router.post("/registro", comprobaciones, authController.registroUsuario);

router.post(
  "/registro-moderador",
  comprobaciones,
  authController.registroModerador
);

router.post("/loggin", comprobaciones, authController.login);

export default router;
