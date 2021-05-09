import { NextFunction, Request, Response } from "express";
import { validationResult } from "express-validator";

export default function validacionErrors(
  req: Request,
  res: Response,
  next: NextFunction
) {
  let errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors });
  }

  next();
}
