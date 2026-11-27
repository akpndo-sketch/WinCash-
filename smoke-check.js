const fs=require('fs');
const s=fs.readFileSync('server.js','utf8');
const required=['CREATE TABLE IF NOT EXISTS messages','CREATE TABLE IF NOT EXISTS notifications','CREATE TABLE IF NOT EXISTS social_posts','CREATE TABLE IF NOT EXISTS post_comments','CREATE TABLE IF NOT EXISTS post_reactions','CREATE TABLE IF NOT EXISTS social_groups','app.get("/api/messages/:userId"','app.post("/api/messages"','app.get("/api/notifications"','app.post("/api/social/posts"','app.post("/api/social/groups"'];
for(const item of required){if(!s.includes(item)){console.error('Missing:',item);process.exit(1)}}
for(const f of ['public/index.html','public/social.html','public/manifest.json','public/sw.js'])if(!fs.existsSync(f)){console.error('Missing file:',f);process.exit(1)}
console.log('WinCash smoke-check OK: schema, API routes and frontend files present.');
