import app from "./app";

async function main() {
  await app.listen(app.get("port"));
  console.log(`servidor en el puerto ${app.get("port")}`);
}

main();
