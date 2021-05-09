import { Schema, model, Document } from "mongoose";

export interface Iusuario extends Document {
  email: string;
  password: string;
  rol: string;
}

let usuarioSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
      trim: true,
    },
    rol: {
      type: String,
      required: true,
    },
  },
  {
    versionKey: false,
  }
);

export default model<Iusuario>("usuario", usuarioSchema);
