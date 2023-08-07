import { Router } from "express";
import usersRouter from "./users.routes.js";
import urlsRouter from "./urls.routes.js";

const router = Router();

router.use(usersRouter);
router.use(urlsRouter);

export default router;
