require("dotenv").config();

const http = require("http");
const express = require("express");
const morgan = require("morgan");
const path = require("path");
const config = require("./config");
const apiRoutes = require("./routes/api");
const webRoutes = require("./routes/web");
const { startScheduler } = require("./scheduler");
const repository = require("./repositories");
const { initCache } = require("./services/cacheService");

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "../views"));

app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "../public")));

app.use("/api", apiRoutes);
app.use("/", apiRoutes);
app.use("/", webRoutes);

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "cve-intel-hub" });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: "Internal server error" });
});

function startHttpServer(startPort) {
  const maxAttempts = 20;

  const tryListen = (port, attemptsLeft) => {
    const server = http.createServer(app);

    server.once("error", (error) => {
      if (error.code === "EADDRINUSE" && attemptsLeft > 0) {
        console.warn(`[BOOT] Port ${port} is busy, trying ${port + 1}...`);
        tryListen(port + 1, attemptsLeft - 1);
        return;
      }

      console.error("Failed to start server", error);
      process.exit(1);
    });

    server.listen(port, () => {
      console.log(`CVE system listening at http://localhost:${port}`);
      startScheduler();
    });
  };

  tryListen(startPort, maxAttempts);
}

async function bootstrap() {
  await repository.init();
  await initCache();
  startHttpServer(config.port);
}

bootstrap().catch((error) => {
  console.error("Failed to bootstrap application", error);
  process.exit(1);
});
