// api/server.js
import { MongoClient, ObjectId } from "mongodb";
import { createClient } from "@supabase/supabase-js";

// ---- ENV (set in Vercel) ----
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB  = process.env.MONGODB_DB || "ms_store";
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

// Admin hardening
const ALLOWED_ADMIN_EMAIL = process.env.ALLOWED_ADMIN_EMAIL || ""; // e.g. owner@email.com
const ADMIN_DEVICE_FP = process.env.ADMIN_DEVICE_FP || "";         // from first trusted device
const ADMIN_IP_ALLOWLIST = (process.env.ADMIN_IP_ALLOWLIST || "").split(",").map(s=>s.trim()).filter(Boolean);

// ---- DB client cache for serverless ----
let cached = global._mongo;
if (!cached) { cached = global._mongo = { conn: null, client: null }; }

async function connectDB(){
  if (cached.conn) return cached.conn;
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(MONGODB_DB);
  cached.conn = { client, db, products: db.collection("products"), orders: db.collection("orders") };
  return cached.conn;
}

// ---- Supabase helper ----
const sb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
async function getUserFromAuthHeader(req){
  const auth = req.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ")? auth.slice(7): null;
  if(!token) return null;
  const { data, error } = await sb.auth.getUser(token);
  if(error || !data?.user) return null;
  return { token, user: data.user };
}

// ---- Admin guard ----
function ipFromReq(req){
  const xf = req.headers.get("x-forwarded-for") || "";
  return xf.split(",")[0]?.trim() || "";
}
function isAdminAllowed({ user, req }){
  if(!user || !user.email) return false;
  if(ALLOWED_ADMIN_EMAIL && user.email.toLowerCase()!==ALLOWED_ADMIN_EMAIL.toLowerCase()) return false;
  if(ADMIN_DEVICE_FP){
    const fp = req.headers.get("x-device-fp") || "";
    if(fp !== ADMIN_DEVICE_FP) return false;
  }
  if(ADMIN_IP_ALLOWLIST.length){
    const ip = ipFromReq(req);
    if(!ADMIN_IP_ALLOWLIST.includes(ip)) return false;
  }
  return true;
}

// ---- Response helpers ----
function json(status, data){
  return new Response(JSON.stringify(data), { status, headers:{ "content-type":"application/json" } });
}
function notFound(){ return json(404, { error:"Not found" }); }

// ---- Router ----
export default async function handler(req){
  const url = new URL(req.url);
  const path = url.pathname;   // e.g. /api/products
  const method = req.method;

  // Health
  if(path.endsWith("/api/health")) return json(200,{ ok:true, time:new Date().toISOString() });

  const { db, products, orders } = await connectDB();

  // ----- PRODUCTS -----
  if(path.endsWith("/api/products") && method==="GET"){
    const list = await products.find().sort({ _id:-1 }).toArray();
    return json(200, list);
  }
  if(path.endsWith("/api/products") && method==="POST"){
    const auth = await getUserFromAuthHeader(req);
    if(!auth || !isAdminAllowed({user:auth.user, req})) return json(401,{ error:"Unauthorized" });
    const body = await req.json();
    const doc = {
      name: String(body.name||"").trim(),
      price: Number(body.price||0),
      category: String(body.category||"").trim(),
      image: String(body.image||"").trim(),
      stock: Number(body.stock||0),
      createdAt: new Date().toISOString()
    };
    if(!doc.name || !doc.price) return json(400,{ error:"Name/Price required" });
    const r = await products.insertOne(doc);
    return json(200,{ _id:r.insertedId, ...doc });
  }
  if(path.match(/\/api\/products\/[a-f0-9]{24}$/) && method==="DELETE"){
    const auth = await getUserFromAuthHeader(req);
    if(!auth || !isAdminAllowed({user:auth.user, req})) return json(401,{ error:"Unauthorized" });
    const id = path.split("/").pop();
    await products.deleteOne({ _id: new ObjectId(id) });
    return json(200,{ ok:true });
  }
  if(path.match(/\/api\/products\/[a-f0-9]{24}$/) && method==="PUT"){
    const auth = await getUserFromAuthHeader(req);
    if(!auth || !isAdminAllowed({user:auth.user, req})) return json(401,{ error:"Unauthorized" });
    const id = path.split("/").pop();
    const body = await req.json();
    const $set = {};
    ["name","price","category","image","stock"].forEach(k=>{ if(body[k]!==undefined) $set[k]=body[k] });
    await products.updateOne({ _id:new ObjectId(id) }, { $set });
    return json(200,{ ok:true });
  }

  // ----- ORDERS -----
  if(path.endsWith("/api/orders") && method==="GET"){
    // admin: list all
    const auth = await getUserFromAuthHeader(req);
    if(!auth || !isAdminAllowed({user:auth.user, req})) return json(401,{ error:"Unauthorized" });
    const list = await orders.find().sort({ _id:-1 }).toArray();
    return json(200, list);
  }

  if(path.endsWith("/api/my-orders") && method==="GET"){
    // customer: own orders
    const auth = await getUserFromAuthHeader(req);
    if(!auth) return json(401,{ error:"Unauthorized" });
    const list = await orders.find({ userId: auth.user.id }).sort({ _id:-1 }).toArray();
    return json(200, list);
  }

  if(path.endsWith("/api/orders") && method==="POST"){
    // create order (must login)
    const auth = await getUserFromAuthHeader(req);
    if(!auth) return json(401,{ error:"Login required" });
    const body = await req.json();
    const items = Array.isArray(body.items)? body.items: [];
    if(!items.length) return json(400,{ error:"Cart empty" });

    // Server-side price verification
    const prodMap = new Map();
    const pids = items.map(i=>new ObjectId(i.id));
    const dbProducts = await products.find({ _id:{ $in:pids } }).toArray();
    dbProducts.forEach(p=>prodMap.set(p._id.toString(), p));

    let total = 0;
    const normalizedItems = [];
    for(const it of items){
      const p = prodMap.get(String(it.id));
      const qty = Math.max(1, Math.min(99, Number(it.qty||0)));
      if(!p || qty<=0) continue;
      const line = p.price * qty;
      total += line;
      normalizedItems.push({ id:p._id, name:p.name, price:p.price, qty });
    }
    if(!normalizedItems.length) return json(400,{ error:"No valid items" });
    const shipping = total>500?0:40;
    const grandTotal = total + shipping;

    const order = {
      userId: auth.user.id,
      email: auth.user.email,
      name: String(body.name||"").trim(),
      phone: String(body.phone||"").trim(),
      address: String(body.address||"").trim(),
      lat: String(body.lat||""),
      lng: String(body.lng||""),
      pay: body.pay||"cod",
      note: String(body.note||""),
      items: normalizedItems,
      subTotal: total,
      shipping,
      total: grandTotal,
      status: "pending",
      createdAt: new Date().toISOString()
    };
    if(!order.address) return json(400,{ error:"Delivery address required" });

    const r = await orders.insertOne(order);
    return json(200,{ _id:r.insertedId, ...order });
  }

  if(path.match(/\/api\/orders\/[a-f0-9]{24}$/) && method==="PUT"){
    // admin: update status
    const auth = await getUserFromAuthHeader(req);
    if(!auth || !isAdminAllowed({user:auth.user, req})) return json(401,{ error:"Unauthorized" });
    const id = path.split("/").pop();
    const body = await req.json();
    const status = String(body.status||"").toLowerCase();
    if(!["pending","processing","delivered","cancelled"].includes(status)) return json(400,{ error:"Invalid status" });
    await orders.updateOne({ _id:new ObjectId(id) }, { $set:{ status } });
    return json(200,{ ok:true });
  }

  return notFound();
}

// Vercel entry
export const config = { runtime: "nodejs20.x" };
