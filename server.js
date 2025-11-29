const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const app = express();
app.use(express.json());
const ADMIN_SECRET = "Inspect.gg-Ax-0";
const dbPath = "./licenses.json";
function loadDB() {
    return JSON.parse(fs.readFileSync(dbPath, "utf8"));
}
function saveDB(data) {
    fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
}
function hashHwid(hwid) {
    return crypto.createHash("sha256").update(hwid).digest("hex");
}
app.post("/api/create", (req, res) => {
    if (req.headers["x-admin-secret"] !== ADMIN_SECRET)
        return res.status(403).json({ error: "unauthorized" });
    const { key, expires } = req.body;
    if (!key) return res.json({ error: "missing_key" });
    const db = loadDB();
    db[key] = {
        key,
        hwid: null,
        status: "active",
        created: Date.now(),
        expires: expires || null,
        uses: 0
    };
    saveDB(db);
    res.json({ ok: true });
});
app.post("/api/verify", (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.json({ error: "missing_key_or_hwid" });
    const db = loadDB();
    const lic = db[key];
    if (!lic) return res.json({ error: "invalid_key" });
    if (lic.expires && Date.now() > lic.expires)
        return res.json({ error: "expired" });
    if (lic.status !== "active")
        return res.json({ error: "inactive" });
    const hashed = hashHwid(hwid);
    if (!lic.hwid) {
        lic.hwid = hashed;
    } else if (lic.hwid !== hashed) {
        return res.json({ error: "hwid_mismatch" });
    }
    lic.uses++;
    lic.lastSeen = Date.now();

    db[key] = lic;
    saveDB(db);

    res.json({
        ok: true,
        key: key,
        expires: lic.expires,
        uses: lic.uses
    });
});

app.listen(3000, () => console.log("HWID auth server running on port 3000"));

