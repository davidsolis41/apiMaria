import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import Usuario from "../models/maria/usuario";

// CONFIGURACIONES SOLO PARA TS

declare global {
  // utilizamos esto para extender la propiedades de Request
  namespace Express {
    interface Request {
      userId: string; //asignamos la nueva propiedad
    }
  }
}

// creamos la interfaz para que no no de error por lo que retorna jwt.verify()
export interface IPayload {
  id: string;
  iat: number;
}

// AQUI EMPIEZA NUESTRO CODIGO

export const verifyToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let token = req.headers["x-access-token"] as string;
  let SECRET = process.env.JWT_SECRET as string;

  if (!token) {
    return res.status(403).json({ msg: "Envia tu token para proceder" });
  }

  try {
    const decoded = jwt.verify(token, SECRET) as any; // asignamos la interfaz

    req.userId = decoded.id;

    console.log(`jwt: ${decoded.id}`);

    next();
  } catch (error) {
    return res.status(401).json({ msg: `Acceso Denegado  ${error}` });
  }
};

export const isModerador = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (!req.userId) {
    return res.status(500).json({
      msg: "Se intenta realizar la accion sin antes validar el token",
    });
  }

  try {
    let user: any = await Usuario.findOne({
      where: { id: req.userId },
      attributes: {
        exclude: ["password", "email"],
      },
    });

    if (user.rol === process.env.ROL_MODERADOR) {
      return next();
    }

    return res.status(403).json({ msg: "No tienes permisos para esta ruta" });
  } catch (error) {
    return res.status(500).json({ error });
  }
};

export const isAdmin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (!req.userId) {
    return res.status(500).json({
      msg: "Se intenta realizar la accion sin antes validar el token",
    });
  }

  try {
    let user: any = await Usuario.findOne({
      where: { id: req.userId },
      attributes: {
        exclude: ["password", "email"],
      },
    });

    if (user.rol === process.env.ROL_ADMIN) {
      return next();
    }

    return res.status(403).json({ msg: "No tienes permisos para esta ruta" });
  } catch (error) {
    return res.status(500).json({ error });
  }
};
