import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { api } from "@shared/routes";
import { z } from "zod";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { insertUserSchema } from "@shared/schema";

const scryptAsync = promisify(scrypt);

// 🔐 OWASP A2: Cryptographic Failures (Secure Password Hashing)
async function hashPassword(password: string) {
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

async function comparePassword(supplied: string, stored: string) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(hashedBuf, suppliedBuf);
}

// 🔐 OWASP A5: Broken Access Control (RBAC Middleware)
function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: "Unauthorized" });
}

function isAdmin(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated() && req.user?.role === "admin") {
    return next();
  }
  res.status(403).json({ message: "Forbidden: Admin access required" });
}

export async function registerRoutes(httpServer: Server, app: Express): Promise<Server> {
  // Session setup
  app.use(
    session({
      secret: process.env.SESSION_SECRET || "secure_secret_key_change_me", // 🔐 OWASP A2: Use strong secrets
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: app.get("env") === "production", // 🔐 OWASP A5: Secure cookies in production
        httpOnly: true, // 🔐 OWASP A5: Prevent XSS access to cookies
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      },
    })
  );

  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await storage.getUserByUsername(username);
        if (!user || !(await comparePassword(password, user.password))) {
          // 🔐 OWASP A2: Generic error message to prevent enumeration
          return done(null, false, { message: "Invalid username or password" });
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    })
  );

  passport.serializeUser((user: any, done) => done(null, user.id));
  passport.deserializeUser(async (id: number, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });

  // --- Auth Routes ---
  app.post(api.auth.register.path, async (req, res) => {
    try {
      const input = api.auth.register.input.parse(req.body);
      const existingUser = await storage.getUserByUsername(input.username);
      if (existingUser) {
        return res.status(400).json({ message: "Username already exists" });
      }

      const hashedPassword = await hashPassword(input.password);
      const user = await storage.createUser({ ...input, password: hashedPassword });

      // Auto-login after register
      req.login(user, async (err) => {
        if (err) throw err;
        await storage.createAuditLog({
          action: "USER_REGISTER",
          userId: user.id,
          details: `User ${user.username} registered with role ${user.role}`,
          ipAddress: req.ip,
        });
        res.status(201).json(user);
      });
    } catch (err) {
      if (err instanceof z.ZodError) {
        res.status(400).json({ message: err.errors[0].message });
      } else {
        res.status(500).json({ message: "Internal server error" });
      }
    }
  });

  app.post(api.auth.login.path, passport.authenticate("local"), async (req, res) => {
    const user = req.user as any;
    await storage.createAuditLog({
      action: "LOGIN_SUCCESS",
      userId: user.id,
      details: "User logged in",
      ipAddress: req.ip,
    });
    res.status(200).json(user);
  });

  app.post(api.auth.logout.path, (req, res, next) => {
    const userId = req.user?.id;
    req.logout((err) => {
      if (err) return next(err);
      if (userId) {
        storage.createAuditLog({
          action: "LOGOUT",
          userId: userId,
          details: "User logged out",
          ipAddress: req.ip,
        }).catch(console.error);
      }
      res.status(200).json({ message: "Logged out" });
    });
  });

  app.get(api.auth.me.path, isAuthenticated, (req, res) => {
    res.json(req.user);
  });

  // --- Task Routes ---
  app.get(api.tasks.list.path, isAuthenticated, async (req, res) => {
    const user = req.user as any;
    // 🔐 OWASP A1: IDOR Protection - Users only see their own tasks unless admin?
    // Requirement: "No user can access another user’s data".
    // "Admin can view all tasks and audit logs" - The list view for tasks might be just own tasks for everyone,
    // or maybe Admin sees all? Let's assume Admin sees all for auditing, but User sees own.
    // Actually, "Admin can view all tasks" is a requirement.
    let tasks;
    if (user.role === 'admin') {
      tasks = await storage.getTasks();
    } else {
      tasks = await storage.getTasksByUserId(user.id);
    }
    res.json(tasks);
  });

  app.post(api.tasks.create.path, isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const input = api.tasks.create.input.parse(req.body);
      const task = await storage.createTask({ ...input, ownerId: user.id });

      await storage.createAuditLog({
        action: "TASK_CREATE",
        userId: user.id,
        details: `Task created: ${task.title}`,
        ipAddress: req.ip,
      });

      res.status(201).json(task);
    } catch (err) {
      if (err instanceof z.ZodError) {
        res.status(400).json({ message: err.errors[0].message });
      } else {
        res.status(500).json({ message: "Internal server error" });
      }
    }
  });

  app.get(api.tasks.get.path, isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const task = await storage.getTask(parseInt(req.params.id));

    if (!task) return res.status(404).json({ message: "Task not found" });

    // 🔐 OWASP A1: IDOR Protection
    if (user.role !== 'admin' && task.ownerId !== user.id) {
       await storage.createAuditLog({
        action: "UNAUTHORIZED_ACCESS_ATTEMPT",
        userId: user.id,
        details: `Attempted to access task ${task.id} owned by user ${task.ownerId}`,
        ipAddress: req.ip,
      });
      return res.status(403).json({ message: "Forbidden" });
    }

    res.json(task);
  });

  app.patch(api.tasks.update.path, isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const taskId = parseInt(req.params.id);
      const task = await storage.getTask(taskId);

      if (!task) return res.status(404).json({ message: "Task not found" });

      // 🔐 OWASP A1: IDOR Protection
      // "Admin can manage users... Normal users manage only their own tasks"
      // Assuming Admin can also update tasks? Requirement says "Admin can view all tasks", doesn't explicitly say edit.
      // But usually Admin can. Let's strictly follow "Normal users: Manage only their own tasks".
      // Admin: "Manage users", "View all tasks". It doesn't explicitly say Admin can EDIT tasks.
      // Safest: Allow Admin to edit, or restrict?
      // Let's allow Admin for now, or maybe restrict to Owner only?
      // Requirement: "No user can access another user's data".
      // Let's restrict to owner for modification to be safe on "Manage only their own tasks" for normal users.
      // What about Admin? "Admin can View all tasks". It doesn't say Modify.
      // I will restrict modification to Owner only, unless it's strictly necessary.
      // Actually, standard RBAC: Admin might need to moderate.
      // I'll allow Admin to be safe, but log it.
      if (user.role !== 'admin' && task.ownerId !== user.id) {
        return res.status(403).json({ message: "Forbidden" });
      }

      const input = api.tasks.update.input.parse(req.body);
      const updatedTask = await storage.updateTask(taskId, input);

      await storage.createAuditLog({
        action: "TASK_UPDATE",
        userId: user.id,
        details: `Task ${taskId} updated. Status: ${updatedTask.status}`,
        ipAddress: req.ip,
      });

      res.json(updatedTask);
    } catch (err) {
      if (err instanceof z.ZodError) {
        res.status(400).json({ message: err.errors[0].message });
      } else {
        res.status(500).json({ message: "Internal server error" });
      }
    }
  });

  app.delete(api.tasks.delete.path, isAuthenticated, async (req, res) => {
    const user = req.user as any;
    const taskId = parseInt(req.params.id);
    const task = await storage.getTask(taskId);

    if (!task) return res.status(404).json({ message: "Task not found" });

    if (user.role !== 'admin' && task.ownerId !== user.id) {
      return res.status(403).json({ message: "Forbidden" });
    }

    await storage.deleteTask(taskId);

    await storage.createAuditLog({
      action: "TASK_DELETE",
      userId: user.id,
      details: `Task ${taskId} deleted`,
      ipAddress: req.ip,
    });

    res.status(204).send();
  });

  // --- Audit Routes ---
  app.get(api.audit.list.path, isAdmin, async (req, res) => {
    const logs = await storage.getAuditLogs();
    res.json(logs);
  });

  // Seed Admin User if not exists
  const existingAdmin = await storage.getUserByUsername("admin");
  if (!existingAdmin) {
    const hashed = await hashPassword("admin123");
    await storage.createUser({
      username: "admin",
      password: hashed,
      role: "admin",
    });
    console.log("Seeded admin user: admin / admin123");
  }

  return httpServer;
}
