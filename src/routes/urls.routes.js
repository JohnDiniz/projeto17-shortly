import { Router } from "express";
import { urlSchema } from "../schemas/urls.schemas.js"
import { validateAuth } from "../middlewares/validateAuth.js";
import { validateSchema } from "../middlewares/validateSchema.js";
import { urlShorten, urlId, urlOpen, deleteUrlId } from "../controllers/urls.controller.js";

const urlsRouter = Router();

urlsRouter.post("/urls/shorten", validateAuth, validateSchema(urlSchema), urlShorten);
urlsRouter.get("/urls/:id", urlId);
urlsRouter.get("/urls/open/:shortUrl", urlOpen);
urlsRouter.delete("/urls/:id", validateAuth, deleteUrlId);

export default urlsRouter