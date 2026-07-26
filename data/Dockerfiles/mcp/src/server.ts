import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

const config = loadConfig(process.env);
const app = createApp({ readiness: async () => true });

app.listen(config.port);
