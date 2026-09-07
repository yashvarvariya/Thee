#!/usr/bin/env bash
set -euo pipefail
cd ~/quantaforge

echo "[1/12] backend/quantaforge/backend/prisma/schema.prisma"
cat > backend/quantaforge/backend/prisma/schema.prisma << 'FILE_EOF_MARK'
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

enum Role {
  OWNER
  ADMIN
  CUSTOMER
}

enum NodeStatus {
  ONLINE
  OFFLINE
  CONNECTING
  ERROR
}

enum VpsStatus {
  INSTALLING
  RUNNING
  STOPPED
  SUSPENDED
  OFFLINE
  ERROR
  DELETING
}

enum Protocol {
  TCP
  UDP
}

model User {
  id           String   @id @default(cuid())
  email        String   @unique
  passwordHash String
  role         Role
  createdAt    DateTime @default(now())

  adminPermission AdminPermission?
  vpsList         Vps[]             @relation("CustomerVps")
  activityLogs    ActivityLog[]
  tickets         Ticket[]
  ticketMessages  TicketMessage[]
}

// One row per ADMIN user. Owners are not subject to this table at all —
// requirePermission() short-circuits to allow for role === OWNER before
// this is ever queried.
model AdminPermission {
  id                  String  @id @default(cuid())
  userId              String  @unique
  user                User    @relation(fields: [userId], references: [id])

  viewVps             Boolean @default(false)
  deployVps           Boolean @default(false)
  startVps            Boolean @default(false)
  stopVps             Boolean @default(false)
  restartVps          Boolean @default(false)
  console             Boolean @default(false)
  suspendVps          Boolean @default(false)
  unsuspendVps        Boolean @default(false)
  deleteVps           Boolean @default(false)
  addPorts            Boolean @default(false)
  removePorts         Boolean @default(false)
  manageUsers         Boolean @default(false)
  manageNodes         Boolean @default(false)
  managePlans         Boolean @default(false)
  billing             Boolean @default(false)
  viewLogs            Boolean @default(false)
  branding            Boolean @default(false)
  settings            Boolean @default(false)
  resourceProtection  Boolean @default(false)
}

model Node {
  id                String     @id @default(cuid())
  name              String
  host              String
  port              Int
  username          String
  encryptedPassword String     // AES-256-GCM ciphertext, never sent to any client
  status            NodeStatus @default(CONNECTING)
  totalCpu          Int
  totalRamMb        Int
  totalStorageMb    Int
  lastCheckedAt     DateTime?
  createdAt         DateTime   @default(now())

  vpsList Vps[]
}

model Vps {
  id               String    @id @default(cuid())
  name             String
  customerId       String
  customer         User      @relation("CustomerVps", fields: [customerId], references: [id])
  nodeId           String
  node             Node      @relation(fields: [nodeId], references: [id])

  status           VpsStatus @default(INSTALLING)
  os               String
  cpuCores         Int
  ramMb            Int
  storageMb        Int
  ipAddress        String?

  // Docker container name on the Node (e.g. "vps-<id>"). Set only after
  // provisioning actually succeeds on the node — null means no real
  // container exists yet (INSTALLING/ERROR) or it was torn down (deleted).
  containerName    String?

  suspendedAt      DateTime?
  suspendedReason  String?
  suspendedBy      String?   // userId of owner/admin, or "system"

  autoSuspend      Boolean   @default(true)
  expiresAt        DateTime?

  // Rolling resource-protection timer state. Nullable = not currently
  // over threshold. Set when a breach starts, cleared the instant usage
  // drops back below threshold — see services/resourceMonitor logic.
  overThresholdSince DateTime?

  deletedAt        DateTime?

  createdAt        DateTime  @default(now())
  ports            Port[]

  @@index([nodeId])
  @@index([customerId])
}

model Port {
  id           String   @id @default(cuid())
  vpsId        String
  vps          Vps      @relation(fields: [vpsId], references: [id])
  nodeId       String   // denormalized for the uniqueness constraint below
  protocol     Protocol
  externalPort Int

  // Prevents duplicate/conflicting port assignment at the DB layer.
  @@unique([nodeId, externalPort])
}

model BrandingSettings {
  id           String  @id @default("singleton")
  panelName    String  @default("QuantaForge")
  logoUrl      String?
  faviconUrl   String?
  supportEmail String?
  supportLink  String?
}

// Singleton row for the owner-configurable auto resource-protection
// system. Read by jobs/resourceMonitor.ts on every tick instead of env
// vars, so the Owner's UI changes take effect without a redeploy.
model ResourceProtectionSettings {
  id                      String  @id @default("singleton")
  enabled                 Boolean @default(false)
  cpuThresholdPct         Int     @default(100)
  ramThresholdPct         Int     @default(100)
  requiredDurationMinutes Int     @default(10)
  allowAdminOverride      Boolean @default(false)
}

model ActivityLog {
  id         String   @id @default(cuid())
  actorId    String?
  actor      User?    @relation(fields: [actorId], references: [id])
  action     String
  targetType String
  targetId   String
  reason     String?
  metadata   Json?
  createdAt  DateTime @default(now())
}

enum TicketStatus {
  OPEN
  CLOSED
}

// Customer support tickets. Any OWNER/ADMIN can view and reply to any
// ticket (support isn't gated behind the fine-grained AdminPermission
// table to avoid a breaking schema change to that model) — a CUSTOMER can
// only see and reply to their own.
model Ticket {
  id         String        @id @default(cuid())
  customerId String
  customer   User          @relation(fields: [customerId], references: [id])
  subject    String
  status     TicketStatus  @default(OPEN)
  createdAt  DateTime      @default(now())
  updatedAt  DateTime      @updatedAt
  messages   TicketMessage[]
}

model TicketMessage {
  id         String   @id @default(cuid())
  ticketId   String
  ticket     Ticket   @relation(fields: [ticketId], references: [id])
  senderId   String
  sender     User     @relation(fields: [senderId], references: [id])
  senderRole Role
  body       String
  createdAt  DateTime @default(now())
}
FILE_EOF_MARK

echo "[2/12] backend/quantaforge/backend/src/routes/tickets.ts"
cat > backend/quantaforge/backend/src/routes/tickets.ts << 'FILE_EOF_MARK'
import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";
import { requireAuth, AuthedRequest } from "../middleware/auth";
import { logActivity } from "../services/activityLog";

const prisma = new PrismaClient();
const router = Router();

router.use(requireAuth);

const isStaff = (role: string) => role === "OWNER" || role === "ADMIN";

const createTicketSchema = z.object({
  subject: z.string().min(3).max(200),
  message: z.string().min(1).max(5000),
});

// POST /tickets — a customer opens a new ticket with a first message.
router.post("/", async (req: AuthedRequest, res) => {
  const parsed = createTicketSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });

  const { subject, message } = parsed.data;

  const ticket = await prisma.ticket.create({
    data: {
      customerId: req.user!.id,
      subject,
      messages: {
        create: {
          senderId: req.user!.id,
          senderRole: req.user!.role,
          body: message,
        },
      },
    },
    include: { messages: true },
  });

  await logActivity({
    actorId: req.user!.id,
    action: "TICKET_CREATED",
    targetType: "Ticket",
    targetId: ticket.id,
  });

  res.status(201).json(ticket);
});

// GET /tickets/mine — the current user's own tickets.
router.get("/mine", async (req: AuthedRequest, res) => {
  const tickets = await prisma.ticket.findMany({
    where: { customerId: req.user!.id },
    orderBy: { updatedAt: "desc" },
    include: { _count: { select: { messages: true } } },
  });
  res.json(tickets);
});

// GET /tickets — every ticket, for staff (OWNER/ADMIN) only.
router.get("/", async (req: AuthedRequest, res) => {
  if (!isStaff(req.user!.role)) return res.status(403).json({ error: "Forbidden" });

  const tickets = await prisma.ticket.findMany({
    orderBy: { updatedAt: "desc" },
    include: {
      customer: { select: { email: true } },
      _count: { select: { messages: true } },
    },
  });
  res.json(tickets);
});

// Shared ownership check: staff can access any ticket, a customer only
// their own. Returns the ticket or sends a response and returns null.
async function loadAccessibleTicket(req: AuthedRequest, res: any) {
  const ticket = await prisma.ticket.findUnique({
    where: { id: req.params.ticketId },
    include: { messages: { orderBy: { createdAt: "asc" } }, customer: { select: { email: true } } },
  });
  if (!ticket) {
    res.status(404).json({ error: "Ticket not found" });
    return null;
  }
  if (!isStaff(req.user!.role) && ticket.customerId !== req.user!.id) {
    res.status(403).json({ error: "Forbidden" });
    return null;
  }
  return ticket;
}

// GET /tickets/:ticketId — full thread.
router.get("/:ticketId", async (req: AuthedRequest, res) => {
  const ticket = await loadAccessibleTicket(req, res);
  if (!ticket) return;
  res.json(ticket);
});

const replySchema = z.object({ body: z.string().min(1).max(5000) });

// POST /tickets/:ticketId/messages — reply on a ticket.
router.post("/:ticketId/messages", async (req: AuthedRequest, res) => {
  const ticket = await loadAccessibleTicket(req, res);
  if (!ticket) return;

  const parsed = replySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });

  const message = await prisma.ticketMessage.create({
    data: {
      ticketId: ticket.id,
      senderId: req.user!.id,
      senderRole: req.user!.role,
      body: parsed.data.body,
    },
  });

  // A reply reopens a closed ticket so it doesn't get lost either side.
  await prisma.ticket.update({
    where: { id: ticket.id },
    data: { updatedAt: new Date(), status: "OPEN" },
  });

  res.status(201).json(message);
});

// POST /tickets/:ticketId/close — either side can mark it resolved.
router.post("/:ticketId/close", async (req: AuthedRequest, res) => {
  const ticket = await loadAccessibleTicket(req, res);
  if (!ticket) return;

  const updated = await prisma.ticket.update({
    where: { id: ticket.id },
    data: { status: "CLOSED" },
  });

  await logActivity({
    actorId: req.user!.id,
    action: "TICKET_CLOSED",
    targetType: "Ticket",
    targetId: ticket.id,
  });

  res.json(updated);
});

export default router;
FILE_EOF_MARK

echo "[3/12] backend/quantaforge/backend/src/routes/me.ts"
cat > backend/quantaforge/backend/src/routes/me.ts << 'FILE_EOF_MARK'
import { Router } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { requireAuth, AuthedRequest } from "../middleware/auth";

const prisma = new PrismaClient();
const router = Router();

const ALL_PERMISSIONS = [
  "viewVps", "deployVps", "startVps", "stopVps", "restartVps", "console",
  "suspendVps", "unsuspendVps", "deleteVps", "addPorts", "removePorts",
  "manageUsers", "manageNodes", "managePlans", "billing", "viewLogs",
  "branding", "settings", "resourceProtection",
] as const;

router.get("/me", requireAuth, async (req: AuthedRequest, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
  if (!user) return res.status(404).json({ error: "User not found" });

  let permissions: Record<string, boolean>;

  if (user.role === "OWNER") {
    // Owner is never restricted — every permission reads true.
    permissions = Object.fromEntries(ALL_PERMISSIONS.map((p) => [p, true]));
  } else if (user.role === "ADMIN") {
    const perms = await prisma.adminPermission.findUnique({ where: { userId: user.id } });
    permissions = Object.fromEntries(ALL_PERMISSIONS.map((p) => [p, perms ? !!(perms as any)[p] : false]));
  } else {
    permissions = {};
  }

  res.json({ id: user.id, email: user.email, role: user.role, permissions });
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8),
});

router.post("/change-password", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = changePasswordSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });

  const { currentPassword, newPassword } = parsed.data;

  const user = await prisma.user.findUnique({ where: { id: req.user!.id } });
  if (!user) return res.status(404).json({ error: "User not found" });

  const valid = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Current password is incorrect" });

  const passwordHash = await bcrypt.hash(newPassword, 12);
  await prisma.user.update({ where: { id: user.id }, data: { passwordHash } });

  res.json({ ok: true });
});

export default router;
FILE_EOF_MARK

echo "[4/12] backend/quantaforge/backend/src/server.ts"
cat > backend/quantaforge/backend/src/server.ts << 'FILE_EOF_MARK'
import "dotenv/config";
import crypto from "crypto";
import http from "http";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { WebSocketServer } from "ws";
import { PrismaClient } from "@prisma/client";

import authRoutes from "./routes/auth";
import meRoutes from "./routes/me";
import nodeRoutes from "./routes/nodes";
import vpsRoutes from "./routes/vps";
import portRoutes from "./routes/ports";
import brandingRoutes from "./routes/branding";
import userRoutes from "./routes/users";
import settingsRoutes from "./routes/settings";
import logRoutes from "./routes/logs";
import ticketRoutes from "./routes/tickets";
import { requireAuth, AuthedRequest } from "./middleware/auth";
import { requireVpsOwnership } from "./middleware/rbac";
import { openConsoleSession } from "./services/consoleRelay";
import { startExpiryCheck } from "./jobs/expiryCheck";
import { startResourceMonitor } from "./jobs/resourceMonitor";

const prisma = new PrismaClient();
const app = express();

// A single bad request should never take the whole Panel down for every
// customer. These two handlers are a last-resort safety net for bugs that
// slip past route-level try/catch (see routes/vps.ts's deploy handler for
// an example of the preferred, specific fix) — they log loudly instead of
// letting Node's default behavior kill the process.
process.on("unhandledRejection", (reason) => {
  // eslint-disable-next-line no-console
  console.error("Unhandled promise rejection (backend stayed up):", reason);
});
process.on("uncaughtException", (err) => {
  // eslint-disable-next-line no-console
  console.error("Uncaught exception (backend stayed up):", err);
});

app.use(cors({ origin: process.env.FRONTEND_ORIGIN, credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.use("/auth", authRoutes);
app.use("/auth", meRoutes); // adds GET /auth/me
app.use("/nodes", nodeRoutes);
app.use("/vps", vpsRoutes);
app.use("/ports", portRoutes);
app.use("/branding", brandingRoutes);
app.use("/users", userRoutes);
app.use("/settings", settingsRoutes);
app.use("/logs", logRoutes);
app.use("/tickets", ticketRoutes);

app.get("/health", (_req, res) => res.json({ ok: true }));

// Express-level fallback: catches errors passed via next(err) or thrown
// synchronously in a route handler. Paired with the process-level handlers
// above for anything that slips past a route's own try/catch.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  // eslint-disable-next-line no-console
  console.error("Unhandled route error:", err);
  if (res.headersSent) return;
  res.status(500).json({ error: "Internal server error" });
});

const server = http.createServer(app);

// ---- Console WebSocket upgrade ---------------------------------------------
// A minimal hand-rolled auth+ownership check for the upgrade path, mirroring
// the HTTP middleware (requireAuth + requireVpsOwnership), since ws upgrades
// don't go through the normal Express middleware chain.
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", async (req, socket, head) => {
  const url = new URL(req.url || "", "http://localhost");
  const match = url.pathname.match(/^\/ws\/console\/([^/]+)$/);
  if (!match) return socket.destroy();

  const vpsId = match[1];
  const sessionToken = url.searchParams.get("session") || crypto.randomUUID();

  // Browsers can't set custom headers on a WS handshake, so the access
  // token travels as a query param over TLS instead — verified exactly
  // like requireAuth does for HTTP routes before anything else happens.
  const token = url.searchParams.get("token");
  let authedUser: { id: string; role: "OWNER" | "ADMIN" | "CUSTOMER" };
  try {
    const payload = jwt.verify(token || "", process.env.JWT_SECRET || "") as {
      userId: string;
      role: "OWNER" | "ADMIN" | "CUSTOMER";
    };
    authedUser = { id: payload.userId, role: payload.role };
  } catch {
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    return socket.destroy();
  }

  const vps = await prisma.vps.findUnique({ where: { id: vpsId }, include: { node: true } });
  if (!vps || vps.deletedAt || vps.status === "SUSPENDED") {
    socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
    return socket.destroy();
  }

  // Mirror requireVpsOwnership(): a customer may only open a console on
  // their own VPS. Owner/admin still need the "console" permission.
  if (authedUser.role === "CUSTOMER" && vps.customerId !== authedUser.id) {
    socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
    return socket.destroy();
  }
  if (authedUser.role === "ADMIN") {
    const perms = await prisma.adminPermission.findUnique({ where: { userId: authedUser.id } });
    if (!perms?.console) {
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      return socket.destroy();
    }
  }
  if (vps.node.status !== "ONLINE") {
    socket.write("HTTP/1.1 503 Service Unavailable\r\n\r\n");
    return socket.destroy();
  }
  if (!vps.containerName) {
    socket.write("HTTP/1.1 409 Conflict\r\n\r\n");
    return socket.destroy();
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    openConsoleSession(sessionToken, vps.id, vps.containerName!, {
      host: vps.node.host,
      port: vps.node.port,
      username: vps.node.username,
      encryptedPassword: vps.node.encryptedPassword,
    }, ws);
  });
});

startExpiryCheck();
startResourceMonitor();

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`QuantaForge API listening on :${PORT}`);
});
FILE_EOF_MARK

echo "[5/12] frontend/src/api/types.ts"
cat > frontend/src/api/types.ts << 'FILE_EOF_MARK'
export type Role = "OWNER" | "ADMIN" | "CUSTOMER";

export type NodeStatus = "ONLINE" | "OFFLINE" | "CONNECTING" | "ERROR";

export type VpsStatus =
  | "INSTALLING" | "RUNNING" | "STOPPED" | "SUSPENDED"
  | "OFFLINE" | "ERROR" | "DELETING";

export type Protocol = "TCP" | "UDP";

export type TicketStatus = "OPEN" | "CLOSED";

export interface TicketMessage {
  id: string;
  ticketId: string;
  senderId: string;
  senderRole: Role;
  body: string;
  createdAt: string;
}

export interface TicketSummary {
  id: string;
  subject: string;
  status: TicketStatus;
  createdAt: string;
  updatedAt: string;
  customer?: { email: string };
  _count: { messages: number };
}

export interface TicketDetail {
  id: string;
  customerId: string;
  subject: string;
  status: TicketStatus;
  createdAt: string;
  updatedAt: string;
  customer: { email: string };
  messages: TicketMessage[];
}

export interface Permissions {
  viewVps: boolean; deployVps: boolean; startVps: boolean; stopVps: boolean;
  restartVps: boolean; console: boolean; suspendVps: boolean; unsuspendVps: boolean;
  deleteVps: boolean; addPorts: boolean; removePorts: boolean; manageUsers: boolean;
  manageNodes: boolean; managePlans: boolean; billing: boolean; viewLogs: boolean;
  branding: boolean; settings: boolean; resourceProtection: boolean;
}

export interface Me {
  id: string;
  email: string;
  role: Role;
  permissions: Partial<Permissions>;
}

export interface NodeSummary {
  id: string;
  name: string;
  status: NodeStatus;
  host?: string;
  port?: number;
  totalCpu?: number;
  totalRamMb?: number;
  totalStorageMb?: number;
  lastCheckedAt?: string | null;
}

export interface Port {
  id: string;
  protocol: Protocol;
  externalPort: number;
}

export interface Vps {
  id: string;
  name: string;
  status: VpsStatus;
  os: string;
  cpuCores: number;
  ramMb: number;
  storageMb: number;
  ipAddress: string | null;
  suspendedAt: string | null;
  suspendedReason: string | null;
  suspendedBy: string | null;
  autoSuspend: boolean;
  expiresAt: string | null;
  createdAt: string;
  node: NodeSummary;
  ports: Port[];
  customer?: { email: string };
}

export interface BrandingSettings {
  panelName: string;
  logoUrl: string | null;
  faviconUrl: string | null;
  supportEmail: string | null;
  supportLink: string | null;
}

export interface AdminUser {
  id: string;
  email: string;
  role: Role;
  createdAt: string;
  adminPermission: Permissions | null;
}

export interface ActivityLogEntry {
  id: string;
  action: string;
  targetType: string;
  targetId: string;
  reason: string | null;
  metadata: any;
  createdAt: string;
  actor: { email: string } | null;
}

export interface ResourceProtectionSettings {
  enabled: boolean;
  cpuThresholdPct: number;
  ramThresholdPct: number;
  requiredDurationMinutes: number;
  allowAdminOverride: boolean;
}
FILE_EOF_MARK

echo "[6/12] frontend/src/api/endpoints.ts"
cat > frontend/src/api/endpoints.ts << 'FILE_EOF_MARK'
import { apiFetch, setAccessToken } from "./client";
import type {
  Me, NodeSummary, Vps, Port, BrandingSettings, AdminUser,
  ActivityLogEntry, ResourceProtectionSettings, Protocol,
  TicketDetail, TicketSummary,
} from "./types";

// ---- Auth -------------------------------------------------------------
export async function login(email: string, password: string) {
  const data = await apiFetch<{ accessToken: string; role: string }>("/auth/login", {
    method: "POST",
    body: { email, password },
  });
  setAccessToken(data.accessToken);
  return data;
}

export async function register(email: string, password: string) {
  const data = await apiFetch<{ accessToken: string; role: string }>("/auth/register", {
    method: "POST",
    body: { email, password },
  });
  setAccessToken(data.accessToken);
  return data;
}

export async function logout() {
  await apiFetch("/auth/logout", { method: "POST" });
  setAccessToken(null);
}

export function fetchMe() {
  return apiFetch<Me>("/auth/me");
}

// ---- Branding (public) --------------------------------------------------
export function fetchPublicBranding() {
  return apiFetch<BrandingSettings>("/branding/public");
}

export function updateBranding(input: Partial<BrandingSettings>) {
  return apiFetch<BrandingSettings>("/branding", { method: "PUT", body: input });
}

// ---- Nodes --------------------------------------------------------------
export function listNodes() {
  return apiFetch<NodeSummary[]>("/nodes");
}

export function createNode(input: {
  name: string; host: string; port: number; username: string; password: string;
  totalCpu: number; totalRamMb: number; totalStorageMb: number;
}) {
  return apiFetch<NodeSummary>("/nodes", { method: "POST", body: input });
}

export function testNodeConnection(nodeId: string) {
  return apiFetch<{ status: string; error?: string }>(`/nodes/${nodeId}/test-connection`, { method: "POST" });
}

export function deleteNode(nodeId: string) {
  return apiFetch<{ ok: true }>(`/nodes/${nodeId}`, { method: "DELETE" });
}

// ---- VPS ------------------------------------------------------------------
export function listMyVps() {
  return apiFetch<Vps[]>("/vps/mine");
}

export function listAllVps() {
  return apiFetch<Vps[]>("/vps");
}

export function deployVps(input: {
  name: string; customerEmail: string; nodeId: string; os: string;
  cpuCores: number; ramMb: number; storageMb: number;
  ports: { protocol: Protocol; externalPort: number }[];
  durationDays: number; autoSuspend: boolean;
}) {
  return apiFetch<Vps>("/vps", { method: "POST", body: input });
}

export function vpsAction(vpsId: string, action: "start" | "stop" | "restart") {
  return apiFetch<Vps>(`/vps/${vpsId}/${action}`, { method: "POST" });
}

export function suspendVps(vpsId: string, reason: string) {
  return apiFetch<Vps>(`/vps/${vpsId}/suspend`, { method: "POST", body: { reason } });
}

export function unsuspendVps(vpsId: string) {
  return apiFetch<Vps>(`/vps/${vpsId}/unsuspend`, { method: "POST" });
}

export function deleteVps(vpsId: string) {
  return apiFetch<{ ok: true }>(`/vps/${vpsId}`, { method: "DELETE", body: { confirm: "DELETE" } });
}

// ---- Ports ------------------------------------------------------------------
export function addPort(vpsId: string, protocol: Protocol, externalPort: number) {
  return apiFetch<Port>("/ports", { method: "POST", body: { vpsId, protocol, externalPort } });
}

export function removePort(portId: string) {
  return apiFetch<{ ok: true }>(`/ports/${portId}`, { method: "DELETE" });
}

// ---- Users / admin permissions -----------------------------------------
export function listUsers() {
  return apiFetch<AdminUser[]>("/users");
}

export function createAdmin(email: string, password: string) {
  return apiFetch<AdminUser>("/users/admins", { method: "POST", body: { email, password } });
}

export function deleteAdmin(userId: string) {
  return apiFetch<{ ok: true }>(`/users/admins/${userId}`, { method: "DELETE" });
}

export function updateAdminPermissions(userId: string, permissions: Record<string, boolean>) {
  return apiFetch(`/users/admins/${userId}/permissions`, { method: "PUT", body: permissions });
}

// ---- Logs -----------------------------------------------------------------
export function listLogs(cursor?: string) {
  const q = cursor ? `?cursor=${cursor}` : "";
  return apiFetch<{ logs: ActivityLogEntry[]; nextCursor: string | null }>(`/logs${q}`);
}

// ---- Resource protection settings ------------------------------------------
export function fetchResourceProtectionSettings() {
  return apiFetch<ResourceProtectionSettings>("/settings/resource-protection");
}

export function updateResourceProtectionSettings(input: Partial<ResourceProtectionSettings>) {
  return apiFetch<ResourceProtectionSettings>("/settings/resource-protection", { method: "PUT", body: input });
}

// ---- Account -----------------------------------------------------------------
export function changePassword(currentPassword: string, newPassword: string) {
  return apiFetch<{ ok: true }>("/auth/change-password", {
    method: "POST",
    body: { currentPassword, newPassword },
  });
}

// ---- Support tickets ---------------------------------------------------------
export function createTicket(subject: string, message: string) {
  return apiFetch<TicketDetail>("/tickets", { method: "POST", body: { subject, message } });
}

export function listMyTickets() {
  return apiFetch<TicketSummary[]>("/tickets/mine");
}

export function listAllTickets() {
  return apiFetch<TicketSummary[]>("/tickets");
}

export function fetchTicket(id: string) {
  return apiFetch<TicketDetail>(`/tickets/${id}`);
}

export function replyToTicket(id: string, body: string) {
  return apiFetch<TicketDetail["messages"][number]>(`/tickets/${id}/messages`, {
    method: "POST",
    body: { body },
  });
}

export function closeTicket(id: string) {
  return apiFetch<TicketDetail>(`/tickets/${id}/close`, { method: "POST" });
}
FILE_EOF_MARK

echo "[7/12] frontend/src/pages/Profile.tsx"
cat > frontend/src/pages/Profile.tsx << 'FILE_EOF_MARK'
import { useState, type FormEvent } from "react";
import { useAuth } from "../context/AuthContext";
import { changePassword } from "../api/endpoints";
import { ApiError } from "../api/client";
import { InlineError } from "../components/Feedback";
import CustomerLayout from "./customer/CustomerLayout";
import AdminLayout from "./admin/AdminLayout";

export default function Profile() {
  const { me } = useAuth();
  const Layout = me?.role === "CUSTOMER" ? CustomerLayout : AdminLayout;

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(false);

    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("New passwords don't match.");
      return;
    }

    setSubmitting(true);
    try {
      await changePassword(currentPassword, newPassword);
      setSuccess(true);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't reach the server. Check your connection.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Layout>
      <h1 className="text-xl font-semibold text-ink mb-6">Profile</h1>

      <div className="qf-card p-6 sm:p-7 max-w-md space-y-6">
        <div>
          <p className="text-sm text-muted">Signed in as</p>
          <p className="text-ink font-medium">{me?.email}</p>
        </div>

        <div className="border-t border-border pt-6">
          <h2 className="text-sm font-semibold text-ink mb-4">Change password</h2>

          <form onSubmit={onSubmit} className="space-y-4" noValidate>
            <div>
              <label className="qf-label" htmlFor="currentPassword">
                Current password
              </label>
              <input
                id="currentPassword"
                type="password"
                autoComplete="current-password"
                className="qf-input"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
            </div>

            <div>
              <label className="qf-label" htmlFor="newPassword">
                New password
              </label>
              <input
                id="newPassword"
                type="password"
                autoComplete="new-password"
                className="qf-input"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>

            <div>
              <label className="qf-label" htmlFor="confirmNewPassword">
                Confirm new password
              </label>
              <input
                id="confirmNewPassword"
                type="password"
                autoComplete="new-password"
                className="qf-input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>

            {error && <InlineError message={error} />}
            {success && (
              <div className="rounded-card border border-online/30 bg-online/10 px-3.5 py-2.5 text-sm text-online">
                Password updated.
              </div>
            )}

            <button type="submit" className="qf-btn-primary w-full" disabled={submitting}>
              {submitting ? "Updating…" : "Update password"}
            </button>
          </form>
        </div>
      </div>
    </Layout>
  );
}
FILE_EOF_MARK

echo "[8/12] frontend/src/pages/Tickets.tsx"
cat > frontend/src/pages/Tickets.tsx << 'FILE_EOF_MARK'
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useApiData } from "../hooks/useApiData";
import { createTicket, listAllTickets, listMyTickets } from "../api/endpoints";
import { ApiError } from "../api/client";
import { Spinner, ErrorState, EmptyState, InlineError } from "../components/Feedback";
import { StatusDot } from "../components/StatusDot";
import CustomerLayout from "./customer/CustomerLayout";
import AdminLayout from "./admin/AdminLayout";
import type { TicketSummary } from "../api/types";

export default function Tickets() {
  const { me } = useAuth();
  const isStaff = me?.role === "OWNER" || me?.role === "ADMIN";
  const Layout = isStaff ? AdminLayout : CustomerLayout;

  const { data: tickets, loading, error, reload } = useApiData<TicketSummary[]>(
    isStaff ? listAllTickets : listMyTickets,
    [isStaff]
  );

  const [showNewForm, setShowNewForm] = useState(false);

  return (
    <Layout>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-ink">Support</h1>
        {!isStaff && (
          <button className="qf-btn-primary" onClick={() => setShowNewForm((s) => !s)}>
            {showNewForm ? "Cancel" : "New ticket"}
          </button>
        )}
      </div>

      {!isStaff && showNewForm && (
        <div className="mb-6">
          <NewTicketForm
            onCreated={() => {
              setShowNewForm(false);
              reload();
            }}
          />
        </div>
      )}

      {loading && <Spinner />}
      {error && <ErrorState message={error} onRetry={reload} />}

      {tickets && tickets.length === 0 && (
        <EmptyState
          title="No tickets yet"
          description={
            isStaff
              ? "Customer support tickets will show up here."
              : "Have an issue or a question? Open a ticket and it'll go straight to the team."
          }
        />
      )}

      {tickets && tickets.length > 0 && (
        <div className="qf-card divide-y divide-border overflow-hidden">
          {tickets.map((t) => (
            <Link
              key={t.id}
              to={`/tickets/${t.id}`}
              className="flex items-center justify-between gap-4 px-4 py-3.5 hover:bg-surface-raised/60 transition-colors"
            >
              <div className="min-w-0">
                <p className="text-ink font-medium truncate">{t.subject}</p>
                <p className="text-xs text-muted truncate">
                  {isStaff && t.customer ? `${t.customer.email} · ` : ""}
                  {t._count.messages} message{t._count.messages === 1 ? "" : "s"}
                </p>
              </div>
              <StatusDot
                label={t.status === "OPEN" ? "Open" : "Closed"}
                tone={t.status === "OPEN" ? "online" : "muted"}
              />
            </Link>
          ))}
        </div>
      )}
    </Layout>
  );
}

function NewTicketForm({ onCreated }: { onCreated: () => void }) {
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (subject.trim().length < 3) {
      setError("Give it a short subject (at least 3 characters).");
      return;
    }
    if (!message.trim()) {
      setError("Describe the issue.");
      return;
    }

    setSubmitting(true);
    try {
      await createTicket(subject.trim(), message.trim());
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't reach the server. Check your connection.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="qf-card p-5 space-y-4">
      <div>
        <label className="qf-label" htmlFor="subject">
          Subject
        </label>
        <input
          id="subject"
          className="qf-input"
          placeholder="e.g. My VPS won't start"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
        />
      </div>
      <div>
        <label className="qf-label" htmlFor="message">
          Message
        </label>
        <textarea
          id="message"
          className="qf-input min-h-[120px] resize-y"
          placeholder="Describe what's happening…"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
      </div>
      {error && <InlineError message={error} />}
      <button type="submit" className="qf-btn-primary" disabled={submitting}>
        {submitting ? "Submitting…" : "Submit ticket"}
      </button>
    </form>
  );
}
FILE_EOF_MARK

echo "[9/12] frontend/src/pages/TicketDetail.tsx"
cat > frontend/src/pages/TicketDetail.tsx << 'FILE_EOF_MARK'
import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useApiData } from "../hooks/useApiData";
import { closeTicket, fetchTicket, replyToTicket } from "../api/endpoints";
import { ApiError } from "../api/client";
import { Spinner, ErrorState, InlineError } from "../components/Feedback";
import { StatusDot } from "../components/StatusDot";
import CustomerLayout from "./customer/CustomerLayout";
import AdminLayout from "./admin/AdminLayout";
import type { TicketDetail as TicketDetailType } from "../api/types";

export default function TicketDetail() {
  const { id } = useParams<{ id: string }>();
  const { me } = useAuth();
  const isStaff = me?.role === "OWNER" || me?.role === "ADMIN";
  const Layout = isStaff ? AdminLayout : CustomerLayout;

  const { data: ticket, loading, error, reload } = useApiData<TicketDetailType>(
    () => fetchTicket(id!),
    [id]
  );

  const [reply, setReply] = useState("");
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);

  async function onReply(e: FormEvent) {
    e.preventDefault();
    if (!reply.trim() || !id) return;
    setSendError(null);
    setSending(true);
    try {
      await replyToTicket(id, reply.trim());
      setReply("");
      reload();
    } catch (err) {
      setSendError(err instanceof ApiError ? err.message : "Couldn't send. Check your connection.");
    } finally {
      setSending(false);
    }
  }

  async function onClose() {
    if (!id) return;
    try {
      await closeTicket(id);
      reload();
    } catch {
      // Non-fatal — the ticket stays open and the button is still there to retry.
    }
  }

  return (
    <Layout>
      <Link to="/tickets" className="text-sm text-muted hover:text-ink">
        ← Back to Support
      </Link>

      {loading && <Spinner />}
      {error && <ErrorState message={error} onRetry={reload} />}

      {ticket && (
        <div className="mt-4">
          <div className="flex items-start justify-between gap-4 mb-6">
            <div>
              <h1 className="text-xl font-semibold text-ink">{ticket.subject}</h1>
              {isStaff && <p className="text-sm text-muted mt-1">{ticket.customer.email}</p>}
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <StatusDot
                label={ticket.status === "OPEN" ? "Open" : "Closed"}
                tone={ticket.status === "OPEN" ? "online" : "muted"}
              />
              {ticket.status === "OPEN" && (
                <button className="qf-btn-secondary" onClick={onClose}>
                  Close ticket
                </button>
              )}
            </div>
          </div>

          <div className="space-y-3 mb-6">
            {ticket.messages.map((m) => {
              const isMine = m.senderId === me?.id;
              const isFromStaff = m.senderRole === "OWNER" || m.senderRole === "ADMIN";
              return (
                <div
                  key={m.id}
                  className={`qf-card p-4 max-w-[85%] ${isMine ? "ml-auto bg-surface-raised" : ""}`}
                >
                  <p className="text-xs text-muted mb-1">
                    {isFromStaff ? "Support team" : "You"} ·{" "}
                    {new Date(m.createdAt).toLocaleString()}
                  </p>
                  <p className="text-ink text-sm whitespace-pre-wrap">{m.body}</p>
                </div>
              );
            })}
          </div>

          <form onSubmit={onReply} className="space-y-3">
            <textarea
              className="qf-input min-h-[100px] resize-y"
              placeholder="Write a reply…"
              value={reply}
              onChange={(e) => setReply(e.target.value)}
            />
            {sendError && <InlineError message={sendError} />}
            <button type="submit" className="qf-btn-primary" disabled={sending || !reply.trim()}>
              {sending ? "Sending…" : "Send reply"}
            </button>
          </form>
        </div>
      )}
    </Layout>
  );
}
FILE_EOF_MARK

echo "[10/12] frontend/src/App.tsx"
cat > frontend/src/App.tsx << 'FILE_EOF_MARK'
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./context/AuthContext";
import { RequireAuth, RequireRole, RequirePermission } from "./components/Guards";

import Login from "./pages/Login";
import Register from "./pages/Register";

import Dashboard from "./pages/customer/Dashboard";
import VpsManage from "./pages/customer/VpsManage";
import CustomerConsoleRoute from "./pages/customer/ConsoleRoute";

import VpsTable from "./pages/admin/VpsTable";
import VpsDetails from "./pages/admin/VpsDetails";
import AdminConsoleRoute from "./pages/admin/ConsoleRoute";
import DeployVps from "./pages/admin/DeployVps";
import Nodes from "./pages/admin/Nodes";
import AddNode from "./pages/admin/AddNode";
import Branding from "./pages/admin/Branding";
import AdminsPermissions from "./pages/admin/AdminsPermissions";
import ResourceProtection from "./pages/admin/ResourceProtection";
import Logs from "./pages/admin/Logs";
import Profile from "./pages/Profile";
import Tickets from "./pages/Tickets";
import TicketDetail from "./pages/TicketDetail";

/** Sends an authenticated user to the right landing page for their role. */
function RoleHome() {
  const { me } = useAuth();
  if (!me) return null;
  return <Navigate to={me.role === "CUSTOMER" ? "/" : "/admin"} replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      {/* ---- Customer ---------------------------------------------------- */}
      <Route
        path="/"
        element={
          <RequireAuth>
            <RequireRole roles={["CUSTOMER"]}>
              <Dashboard />
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/vps/:id"
        element={
          <RequireAuth>
            <RequireRole roles={["CUSTOMER"]}>
              <VpsManage />
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/vps/:id/console"
        element={
          <RequireAuth>
            <RequireRole roles={["CUSTOMER"]}>
              <CustomerConsoleRoute />
            </RequireRole>
          </RequireAuth>
        }
      />

      {/* ---- Shared (any authenticated role) ------------------------------ */}
      <Route
        path="/profile"
        element={
          <RequireAuth>
            <Profile />
          </RequireAuth>
        }
      />
      <Route
        path="/tickets"
        element={
          <RequireAuth>
            <Tickets />
          </RequireAuth>
        }
      />
      <Route
        path="/tickets/:id"
        element={
          <RequireAuth>
            <TicketDetail />
          </RequireAuth>
        }
      />

      {/* ---- Admin / Owner -------------------------------------------------- */}
      <Route
        path="/admin"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="viewVps">
                <VpsTable />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/vps/:id"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="viewVps">
                <VpsDetails />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/vps/:id/console"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="console">
                <AdminConsoleRoute />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/deploy"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="deployVps">
                <DeployVps />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/nodes"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="manageNodes">
                <Nodes />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/nodes/add"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="manageNodes">
                <AddNode />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/branding"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="branding">
                <Branding />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/admins"
        element={<Navigate to="/admin/permissions" replace />}
      />
      <Route
        path="/admin/permissions"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="manageUsers">
                <AdminsPermissions />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/resource-protection"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="resourceProtection">
                <ResourceProtection />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />
      <Route
        path="/admin/logs"
        element={
          <RequireAuth>
            <RequireRole roles={["OWNER", "ADMIN"]}>
              <RequirePermission permission="viewLogs">
                <Logs />
              </RequirePermission>
            </RequireRole>
          </RequireAuth>
        }
      />

      {/* ---- Fallback -------------------------------------------------------- */}
      <Route
        path="*"
        element={
          <RequireAuth>
            <RoleHome />
          </RequireAuth>
        }
      />
    </Routes>
  );
}
FILE_EOF_MARK

echo "[11/12] frontend/src/pages/customer/CustomerLayout.tsx"
cat > frontend/src/pages/customer/CustomerLayout.tsx << 'FILE_EOF_MARK'
import type { ReactNode } from "react";
import { AppShell } from "../../components/AppShell";

export default function CustomerLayout({ children }: { children: ReactNode }) {
  return (
    <AppShell
      navItems={[
        { to: "/", label: "Dashboard", end: true },
        { to: "/tickets", label: "Support" },
        { to: "/profile", label: "Profile" },
      ]}
      roleLabel="Customer"
    >
      {children}
    </AppShell>
  );
}
FILE_EOF_MARK

echo "[12/12] frontend/src/pages/admin/AdminLayout.tsx"
cat > frontend/src/pages/admin/AdminLayout.tsx << 'FILE_EOF_MARK'
import type { ReactNode } from "react";
import { AppShell, type NavItem } from "../../components/AppShell";
import { useAuth } from "../../context/AuthContext";

export default function AdminLayout({ children }: { children: ReactNode }) {
  const { me, can } = useAuth();

  const allItems: Array<NavItem & { requires?: Parameters<typeof can>[0] }> = [
    { to: "/admin", label: "VPS", end: true, requires: "viewVps" },
    { to: "/admin/deploy", label: "Deploy VPS", requires: "deployVps" },
    { to: "/admin/nodes", label: "Nodes", requires: "manageNodes" },
    { to: "/admin/permissions", label: "Admins & Permissions", requires: "manageUsers" },
    { to: "/admin/resource-protection", label: "Resource Protection", requires: "resourceProtection" },
    { to: "/admin/branding", label: "Branding", requires: "branding" },
    { to: "/admin/logs", label: "Activity Logs", requires: "viewLogs" },
    { to: "/tickets", label: "Support Tickets" },
    { to: "/profile", label: "Profile" },
  ];

  const navItems = allItems.filter((item) => !item.requires || can(item.requires));

  return (
    <AppShell navItems={navItems} roleLabel={me?.role === "OWNER" ? "Owner" : "Admin"}>
      {children}
    </AppShell>
  );
}
FILE_EOF_MARK

echo "Files patched. Running Prisma migration for Ticket/TicketMessage tables..."
cd ~/quantaforge/backend/quantaforge/backend
CI=true npx prisma generate
CI=true npx prisma migrate dev --name add_support_tickets_and_password_change

echo "Building backend..."
npm run build

echo "Building frontend..."
cd ~/quantaforge/frontend
npm run build

echo "Restarting services..."
sudo systemctl restart quantaforge-backend
sleep 2
sudo systemctl status quantaforge-backend --no-pager
sudo systemctl reload nginx

echo ""
echo "Done. New: /tickets (Support) and /profile (password change) for every role."
