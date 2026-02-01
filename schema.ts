import { pgTable, text, serial, integer, boolean, timestamp, varchar } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from "drizzle-orm";

// 🔐 Users Table (OWASP A2: Identification and Authentication)
// Stores minimal user info. Passwords must be hashed.
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(), // Hashed password (scrypt)
  role: text("role", { enum: ["admin", "user"] }).default("user").notNull(), // RBAC Role
  createdAt: timestamp("created_at").defaultNow(),
});

// 🔐 Tasks Table (OWASP A5: Broken Access Control)
// Tasks are linked to owners to prevent IDOR.
export const tasks = pgTable("tasks", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description"),
  status: text("status", { enum: ["pending", "in_progress", "completed"] }).default("pending").notNull(),
  ownerId: integer("owner_id").references(() => users.id).notNull(), // Ownership for IDOR protection
  createdAt: timestamp("created_at").defaultNow(),
});

// 🔐 Audit Logs Table (OWASP A10: Security Logging and Monitoring)
// Tracks security-critical events.
export const auditLogs = pgTable("audit_logs", {
  id: serial("id").primaryKey(),
  action: text("action").notNull(), // e.g., "LOGIN_SUCCESS", "TASK_CREATE", "LOGIN_FAILURE"
  userId: integer("user_id").references(() => users.id), // Nullable for failed logins
  details: text("details"), // Contextual info
  ipAddress: text("ip_address"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  tasks: many(tasks),
  auditLogs: many(auditLogs),
}));

export const tasksRelations = relations(tasks, ({ one }) => ({
  owner: one(users, {
    fields: [tasks.ownerId],
    references: [users.id],
  }),
}));

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  user: one(users, {
    fields: [auditLogs.userId],
    references: [users.id],
  }),
}));

// Schemas with Zod (OWASP A1: Injection Prevention - Input Validation)
export const insertUserSchema = createInsertSchema(users).omit({ id: true, createdAt: true });
export const insertTaskSchema = createInsertSchema(tasks).omit({ id: true, createdAt: true, ownerId: true });
export const insertAuditLogSchema = createInsertSchema(auditLogs).omit({ id: true, createdAt: true });

// Types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Task = typeof tasks.$inferSelect;
export type InsertTask = z.infer<typeof insertTaskSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
