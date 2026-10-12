const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "polls.json");

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) throw new Error("Set ADMIN_PASSWORD to at least 12 characters.");
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error("Set SESSION_SECRET to a random value of at least 32 characters.");
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({ votes: [] }, null, 2));

const QUESTIONS = [
  { id:"era", title:"Which era feels right for Crimson OS?", description:"The big community direction question.", options:["2016–2018 classic era","2020–2024 modern era","A mix of both","Neither / something else"] },
  { id:"aesthetic", title:"What visual identity should it have?", description:"Pick the overall aesthetic you want to see.", options:["Steam-inspired / PC gaming","Regular and clean","Unique and experimental","Classic blocky","Modern and realistic"] },
  { id:"graphics", title:"What graphics direction do you prefer?", description:"Choose the look that would keep you coming back.", options:["Flat shading and crisp shadows","Advanced lighting and reflections","Stylized materials and bold colors","Realistic textures","A balanced mix"] },
  { id:"atmosphere", title:"What atmosphere should it create?", description:"What should the experience feel like?", options:["Cozy and nostalgic","Dark and cinematic","Bright and playful","Mysterious and atmospheric","Lived-in and realistic"] },
  { id:"future", title:"Where should Crimson OS go next?", description:"Help prioritize future development.", options:["Preserve the classic look","Push modern graphics further","Mix classic and modern","Build a totally unique style","Let each game choose its identity"] }
];
function readStore() { try { return JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); } catch { return { votes: [] }; } }
function writeStore(store) { const tmp = DATA_FILE + ".tmp"; fs.writeFileSync(tmp, JSON.stringify(store, null, 2)); fs.renameSync(tmp, DATA_FILE); }
function safeVote(v) { return { id:v.id, username:v.username, anonymous:v.anonymous, answers:v.answers, comment:v.comment, createdAt:v.createdAt }; }
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc:["'self'"], scriptSrc:["'self'","'unsafe-inline'","https://cdn.socket.io"], styleSrc:["'self'","'unsafe-inline'"], imgSrc:["'self'","data:","https:"], connectSrc:["'self'","ws:","wss:"] } } }));
app.use(express.json({limit:"30kb"}));
app.use(session({ secret:SESSION_SECRET, resave:false, saveUninitialized:false, cookie:{ httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production", maxAge:8*60*60*1000 } }));
app.use("/api/admin/login", rateLimit({ windowMs:15*60*1000, limit:10, standardHeaders:true, legacyHeaders:false }));
app.use(express.static(path.join(__dirname,"public")));
app.get("/health", (_req,res)=>res.json({ok:true}));
app.get("/api/questions", (_req,res)=>res.json(QUESTIONS));
app.get("/api/results", (_req,res)=>{
 const votes=readStore().votes; const results=QUESTIONS.map(q=>({id:q.id,title:q.title,options:q.options,total:votes.filter(v=>v.answers[q.id]).length,counts:Object.fromEntries(q.options.map(o=>[o,votes.filter(v=>v.answers[q.id]===o).length]))}));
 res.json({results, totalVotes:votes.length});
});
app.post("/api/vote", rateLimit({windowMs:60*60*1000,limit:20,standardHeaders:true,legacyHeaders:false}), (req,res)=>{
 const body=req.body||{}, answers=body.answers;
 if(!answers||typeof answers!=="object") return res.status(400).json({error:"Choose an answer for at least one poll."});
 const valid={}; for(const q of QUESTIONS) if(answers[q.id]) { if(!q.options.includes(answers[q.id])) return res.status(400).json({error:"One of those choices is not valid."}); valid[q.id]=answers[q.id]; }
 if(!Object.keys(valid).length) return res.status(400).json({error:"Choose an answer for at least one poll."});
 const anonymous=!!body.anonymous;
 const username=anonymous?"Anonymous":String(body.username||"").trim().slice(0,32)||"Guest";
 const comment=String(body.comment||"").trim().slice(0,500);
 const store=readStore();
 store.votes.push({id:crypto.randomUUID(),username,anonymous,answers:valid,comment,createdAt:new Date().toISOString()});
 writeStore(store);
 const results=QUESTIONS.map(q=>({id:q.id,title:q.title,options:q.options,total:store.votes.filter(v=>v.answers[q.id]).length,counts:Object.fromEntries(q.options.map(o=>[o,store.votes.filter(v=>v.answers[q.id]===o).length]))}));
 res.json({ok:true,totalVotes:store.votes.length,results});
});
function requireAdmin(req,res,next){if(req.session&&req.session.admin)return next();return res.status(401).json({error:"Admin sign-in required."});}
app.post("/api/admin/login",(req,res)=>{if(typeof req.body.password!=="string"||!crypto.timingSafeEqual(Buffer.from(crypto.createHash("sha256").update(req.body.password).digest("hex")),Buffer.from(crypto.createHash("sha256").update(ADMIN_PASSWORD).digest("hex")))) return res.status(401).json({error:"Incorrect password."});req.session.admin=true;res.json({ok:true});});
app.post("/api/admin/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/admin/submissions",requireAdmin,(_req,res)=>{const votes=readStore().votes;res.json({votes:votes.slice().reverse().map(safeVote),questions:QUESTIONS,totalVotes:votes.length});});
app.delete("/api/admin/submissions/:id",requireAdmin,(req,res)=>{const store=readStore();const before=store.votes.length;store.votes=store.votes.filter(v=>v.id!==req.params.id);if(store.votes.length===before)return res.status(404).json({error:"Submission not found."});writeStore(store);res.json({ok:true});});
app.get("/admin",(_req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.listen(PORT,"0.0.0.0",()=>console.log("Crimson OS Preferences listening on "+PORT));