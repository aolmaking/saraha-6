require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const { Schema, model, isValidObjectId } = mongoose;

const accountSchema = new Schema(
  {
    handle: { type: String, required: true, unique: true, lowercase: true, trim: true, minlength: 3, maxlength: 30 },
    secretHash: { type: String, required: true, select: false },
  },
  { timestamps: true }
);

const hiddenNoteSchema = new Schema(
  {
    author: { type: Schema.Types.ObjectId, ref: "Account", required: true, select: false },
    recipient: { type: Schema.Types.ObjectId, ref: "Account", required: true, index: true },
    body: { type: String, required: true, trim: true, maxlength: 2000 },
  },
  { timestamps: true }
);

const revealAskSchema = new Schema(
  {
    note: { type: Schema.Types.ObjectId, ref: "HiddenNote", required: true, unique: true },
    asker: { type: Schema.Types.ObjectId, ref: "Account", required: true },
    holder: { type: Schema.Types.ObjectId, ref: "Account", required: true, index: true },
    state: { type: String, enum: ["pending", "accepted", "rejected"], default: "pending" },
  },
  { timestamps: true }
);

const chatRoomSchema = new Schema(
  {
    note: { type: Schema.Types.ObjectId, ref: "HiddenNote", required: true, unique: true },
    members: { type: [{ type: Schema.Types.ObjectId, ref: "Account" }], required: true, index: true },
  },
  { timestamps: true }
);

const chatEntrySchema = new Schema(
  {
    room: { type: Schema.Types.ObjectId, ref: "ChatRoom", required: true, index: true },
    from: { type: Schema.Types.ObjectId, ref: "Account", required: true },
    body: { type: String, required: true, trim: true, maxlength: 2000 },
  },
  { timestamps: true }
);

const Account = model("Account", accountSchema);
const HiddenNote = model("HiddenNote", hiddenNoteSchema);
const RevealAsk = model("RevealAsk", revealAskSchema);
const ChatRoom = model("ChatRoom", chatRoomSchema);
const ChatEntry = model("ChatEntry", chatEntrySchema);

class HttpFailure extends Error {
  constructor(code, text) {
    super(text);
    this.code = code;
  }
}

const wrap = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);

const cleanText = (value, label) => {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new HttpFailure(400, `${label} is required`);
  }
  if (value.trim().length > 2000) {
    throw new HttpFailure(400, `${label} is too long`);
  }
  return value.trim();
};

const requireId = (value, label) => {
  if (typeof value !== "string" || !isValidObjectId(value)) {
    throw new HttpFailure(400, `${label} is invalid`);
  }
  return value;
};

const guard = wrap(async (req, res, next) => {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    throw new HttpFailure(401, "Authentication required");
  }
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    throw new HttpFailure(401, "Invalid or expired token");
  }
  const account = await Account.findById(payload.sub);
  if (!account) {
    throw new HttpFailure(401, "Account no longer exists");
  }
  req.me = account;
  next();
});

const issueToken = (account) =>
  jwt.sign({ sub: account._id.toString() }, process.env.JWT_SECRET, { expiresIn: "7d" });

const app = express();
app.use(express.json({ limit: "20kb" }));

app.post(
  "/api/auth/register",
  wrap(async (req, res) => {
    const handle = cleanText(req.body.handle, "handle");
    const secret = cleanText(req.body.password, "password");
    if (handle.length < 3 || handle.length > 30) {
      throw new HttpFailure(400, "handle must be between 3 and 30 characters");
    }
    if (secret.length < 6) {
      throw new HttpFailure(400, "password must be at least 6 characters");
    }
    const taken = await Account.exists({ handle: handle.toLowerCase() });
    if (taken) {
      throw new HttpFailure(409, "handle is already taken");
    }
    const secretHash = await bcrypt.hash(secret, 10);
    const account = await Account.create({ handle, secretHash });
    res.status(201).json({ id: account._id, handle: account.handle, token: issueToken(account) });
  })
);

app.post(
  "/api/auth/login",
  wrap(async (req, res) => {
    const handle = cleanText(req.body.handle, "handle");
    const secret = cleanText(req.body.password, "password");
    const account = await Account.findOne({ handle: handle.toLowerCase() }).select("+secretHash");
    const matches = account ? await bcrypt.compare(secret, account.secretHash) : false;
    if (!matches) {
      throw new HttpFailure(401, "Wrong handle or password");
    }
    res.json({ id: account._id, handle: account.handle, token: issueToken(account) });
  })
);

app.post(
  "/api/notes",
  guard,
  wrap(async (req, res) => {
    const targetHandle = cleanText(req.body.recipientHandle, "recipientHandle").toLowerCase();
    const body = cleanText(req.body.body, "body");
    const target = await Account.findOne({ handle: targetHandle });
    if (!target) {
      throw new HttpFailure(404, "Recipient not found");
    }
    if (target._id.equals(req.me._id)) {
      throw new HttpFailure(400, "You cannot send a note to yourself");
    }
    const note = await HiddenNote.create({ author: req.me._id, recipient: target._id, body });
    res.status(201).json({ id: note._id, body: note.body, createdAt: note.createdAt });
  })
);

app.get(
  "/api/notes/inbox",
  guard,
  wrap(async (req, res) => {
    const notes = await HiddenNote.find({ recipient: req.me._id }).select("+author").sort({ createdAt: -1 });
    const asks = await RevealAsk.find({ note: { $in: notes.map((n) => n._id) } });
    const askByNote = new Map(asks.map((a) => [a.note.toString(), a]));
    const accepted = notes.filter((n) => askByNote.get(n._id.toString())?.state === "accepted");
    const authors = await Account.find({ _id: { $in: accepted.map((n) => n.author) } });
    const authorById = new Map(authors.map((a) => [a._id.toString(), a]));
    const rooms = await ChatRoom.find({ note: { $in: accepted.map((n) => n._id) } });
    const roomByNote = new Map(rooms.map((r) => [r.note.toString(), r]));

    const output = notes.map((n) => {
      const ask = askByNote.get(n._id.toString());
      const item = {
        id: n._id,
        body: n.body,
        createdAt: n.createdAt,
        revealState: ask ? ask.state : "none",
      };
      if (ask && ask.state === "accepted") {
        const author = authorById.get(n.author.toString());
        item.author = { id: author._id, handle: author.handle };
        const room = roomByNote.get(n._id.toString());
        item.roomId = room ? room._id : null;
      }
      return item;
    });
    res.json(output);
  })
);

app.post(
  "/api/notes/:noteId/reveal-asks",
  guard,
  wrap(async (req, res) => {
    const noteId = requireId(req.params.noteId, "noteId");
    const note = await HiddenNote.findOne({ _id: noteId, recipient: req.me._id }).select("+author");
    if (!note) {
      throw new HttpFailure(404, "Note not found");
    }
    const existing = await RevealAsk.findOne({ note: note._id });
    if (existing) {
      throw new HttpFailure(409, `A reveal request already exists for this note (${existing.state})`);
    }
    let ask;
    try {
      ask = await RevealAsk.create({ note: note._id, asker: req.me._id, holder: note.author, state: "pending" });
    } catch (err) {
      if (err && err.code === 11000) {
        throw new HttpFailure(409, "A reveal request already exists for this note");
      }
      throw err;
    }
    res.status(201).json({ id: ask._id, note: ask.note, state: ask.state, createdAt: ask.createdAt });
  })
);

app.get(
  "/api/reveal-asks",
  guard,
  wrap(async (req, res) => {
    const filter = { holder: req.me._id };
    if (req.query.state !== undefined) {
      if (!["pending", "accepted", "rejected"].includes(req.query.state)) {
        throw new HttpFailure(400, "state filter is invalid");
      }
      filter.state = req.query.state;
    }
    const asks = await RevealAsk.find(filter)
      .sort({ createdAt: -1 })
      .populate({ path: "asker", select: "handle" })
      .populate({ path: "note", select: "body createdAt" });
    res.json(
      asks.map((a) => ({
        id: a._id,
        state: a.state,
        createdAt: a.createdAt,
        asker: { id: a.asker._id, handle: a.asker.handle },
        note: { id: a.note._id, body: a.note.body, createdAt: a.note.createdAt },
      }))
    );
  })
);

app.patch(
  "/api/reveal-asks/:askId",
  guard,
  wrap(async (req, res) => {
    const askId = requireId(req.params.askId, "askId");
    const decision = req.body.decision;
    if (decision !== "accept" && decision !== "reject") {
      throw new HttpFailure(400, "decision must be accept or reject");
    }
    const owned = await RevealAsk.findOne({ _id: askId, holder: req.me._id });
    if (!owned) {
      throw new HttpFailure(404, "Request not found");
    }
    const nextState = decision === "accept" ? "accepted" : "rejected";
    const ask = await RevealAsk.findOneAndUpdate(
      { _id: askId, holder: req.me._id, state: "pending" },
      { state: nextState },
      { new: true }
    );
    if (!ask) {
      throw new HttpFailure(409, `Request was already ${owned.state}`);
    }
    if (nextState === "rejected") {
      return res.json({ id: ask._id, state: ask.state });
    }
    let room;
    try {
      room = await ChatRoom.create({ note: ask.note, members: [ask.holder, ask.asker] });
    } catch (err) {
      await RevealAsk.updateOne({ _id: ask._id }, { state: "pending" });
      throw err;
    }
    res.json({ id: ask._id, state: ask.state, roomId: room._id });
  })
);

const loadRoomForMember = async (roomId, accountId) => {
  const room = await ChatRoom.findById(requireId(roomId, "roomId"));
  if (!room) {
    throw new HttpFailure(404, "Conversation not found");
  }
  if (!room.members.some((m) => m.equals(accountId))) {
    throw new HttpFailure(403, "You are not part of this conversation");
  }
  return room;
};

app.get(
  "/api/rooms",
  guard,
  wrap(async (req, res) => {
    const rooms = await ChatRoom.find({ members: req.me._id }).sort({ createdAt: -1 });
    res.json(rooms.map((r) => ({ id: r._id, note: r.note, members: r.members, createdAt: r.createdAt })));
  })
);

app.post(
  "/api/rooms/:roomId/entries",
  guard,
  wrap(async (req, res) => {
    const room = await loadRoomForMember(req.params.roomId, req.me._id);
    const body = cleanText(req.body.body, "body");
    const entry = await ChatEntry.create({ room: room._id, from: req.me._id, body });
    res.status(201).json({ id: entry._id, room: entry.room, from: entry.from, body: entry.body, createdAt: entry.createdAt });
  })
);

app.get(
  "/api/rooms/:roomId/entries",
  guard,
  wrap(async (req, res) => {
    const room = await loadRoomForMember(req.params.roomId, req.me._id);
    const entries = await ChatEntry.find({ room: room._id }).sort({ createdAt: 1 });
    res.json(entries.map((e) => ({ id: e._id, from: e.from, body: e.body, createdAt: e.createdAt })));
  })
);

app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

app.use((err, req, res, next) => {
  if (err instanceof HttpFailure) {
    return res.status(err.code).json({ message: err.message });
  }
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Malformed JSON body" });
  }
  if (err && err.name === "ValidationError") {
    return res.status(400).json({ message: err.message });
  }
  console.error(err);
  res.status(500).json({ message: "Internal server error" });
});

const boot = async () => {
  if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
    console.error("MONGO_URI and JWT_SECRET must be set");
    process.exit(1);
  }
  await mongoose.connect(process.env.MONGO_URI);
  await Promise.all([Account.init(), HiddenNote.init(), RevealAsk.init(), ChatRoom.init(), ChatEntry.init()]);
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Server listening on port ${port}`));
};

boot().catch((err) => {
  console.error(err);
  process.exit(1);
});
